#!/bin/sh
#
# Release script
#

LIBRARY="two-factor-auth"
LOCAL_DIR="$HOME/svn/local/$LIBRARY"

#############################################################
# check initial stuff

bad=0

git status | head -1 | fgrep master > /dev/null 2>&1
if [ $? -ne 0 ]; then
    /bin/echo "Should be on master branch."
    git status | head -1
    bad=1
fi

head -1 src/main/javadoc/doc-files/changelog.txt | fgrep '?' > /dev/null 2>&1
if [ $? -ne 1 ]; then
    /bin/echo "No question-marks (?) can be in the ChangeLog top line."
    head -1 src/main/javadoc/doc-files/changelog.txt
    bad=1
fi

cd $LOCAL_DIR
git status | grep 'nothing to commit'
if [ $? -ne 0 ]; then
    /bin/echo "Files not checked-in"
    git status
    bad=1
fi

#############################################################
# check maven settings

grep sonatype-nexus-snapshots $HOME/.m2/settings.xml > /dev/null 2>&1
if [ $? -ne 0 ]; then
    /bin/echo "Can't find sonatype info in the maven settings.xml file"
    bad=1
fi

#############################################################

release=$(grep version pom.xml | grep SNAPSHOT | head -1 | cut -f2 -d\> | cut -f1 -d\-)

/bin/echo ""
/bin/echo "------------------------------------------------------- "
/bin/echo -n "Enter release number [$release]: "
read rel
if [ "$rel" != "" ]; then
    release=$rel
fi

#############################################################
# check docs:

cd $LOCAL_DIR
ver=$(head -1 src/main/javadoc/doc-files/changelog.txt | cut -f1 -d:)
if [ "$release" != "$ver" ]; then
    /bin/echo "Change log top line version seems wrong:"
    head -1 src/main/javadoc/doc-files/changelog.txt
    bad=1
fi

grep -q $release README.md
if [ $? != 0 ]; then
    /bin/echo "Could not find $release in README.md"
    bad=1
fi

if [ -r "src/main/doc/$LIBRARY.texi" ]; then
    ver=$(grep "^@set ${LIBRARY}_version" src/main/doc/$LIBRARY.texi | cut -f3 -d' ')
    if [ "$release" != "$ver" ]; then
	/bin/echo "$LIBRARY.texi version seems wrong:"
	grep "^@set ${LIBRARY}_version" src/main/doc/$LIBRARY.texi
	bad=1
    fi
fi

if [ -r "src/main/javadoc/doc-files/$LIBRARY.html" ]; then
    grep "Version $release" src/main/javadoc/doc-files/$LIBRARY.html > /dev/null
    if [ $? -ne 0 ]; then
	/bin/echo "javadoc doc-files $LIBRARY.html version seems wrong:"
	grep "Version " src/main/javadoc/doc-files/$LIBRARY.html
	bad=1
    fi
fi

if [ $bad -ne 0 ]; then
    echo "Please fix the previous error and re-run"
    exit 1
fi

#############################################################
# run tests

cd $LOCAL_DIR
mvn test || exit 1

#############################################################

/bin/echo ""
/bin/echo "------------------------------------------------------- "
/bin/echo "Releasing version '$release'"
sleep 3

# remove the local and remote tag if any
tag="$LIBRARY-$release"
git tag -d $tag 2> /dev/null
git push --delete origin $tag 2> /dev/null

#############################################################
# releasing to sonatype

/bin/echo ""
/bin/echo ""
/bin/echo -n "Should we release to sonatype [y]: "
read cont
if [ "$cont" = "" -o "$cont" = "y" ]; then
    cd $LOCAL_DIR
    mvn -P st release:clean || exit 1
    mvn -P st release:prepare || ( /bin/echo "Maybe use mvn release:rollback to rollback"; exit 1 )
    mvn -P st release:perform || ( /bin/echo "Maybe use mvn release:rollback to rollback"; exit 1 )

    /bin/echo ""
    /bin/echo ""
fi
