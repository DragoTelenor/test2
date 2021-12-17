#! /usr/bin/env bash
#
# This script do the following:
# - Scan File System for ALL files with .jar extension
# - Check if it contains log4j V1 or V2 Logger.class 
# - Obtains log4j version via few different methods: pom.xml, MANIFEST.MF or log4j.dtd file
# - Check if vulnerable log4j V2 JndiLookup.class exists in jar file
# - A TAB delimited CSV report file is created with following fields: 
#
#   jar_file_name	log4j_version	JndiLookup.class_path
#
####################
#
# 2021-12-16
#
# - Enhanced version detecting techniques;
# - Adding jar support in case unzip is missing. jar could take more than 4 times slower scanning;
# - Check for required shell tools availability;
# - Error reporting in CSV file;
#
# 2021-12-15,  velin.getov@cetinbg.bg
#
# - Initial Version;
#
####################

HOST=$(hostname)
DATE=$(date +%Y%m%d)
REPORT_DIR="/root"
TEMP_DIR="/tmp"
REPORT_FILE="log4j-report-${HOST}-${DATE}.csv"

function my_exit() {
  ERR=$1
  echo -e "$HOST\t$(uname -a)\t$ERR" >> ${REPORT_DIR}/${REPORT_FILE}
  echo 1>&2 $ERR
  exit 1
}

function findInArchive() {
  file=$1
  arch=$2

  if [ -n "$USE_JAR" ]; then
    fFile=$(jar 2>/dev/null tf "$arch" | grep "$file")
  else
    fFile=$(unzip 2>/dev/null -t "$arch" | grep "$file")
  fi
}

function extractFile {
  file=$1
  arch=$2

  cd $TEMP_DIR || my_exit "Could not cd ${TEMP_DIR}. Exit!"
  rm -rf "${TEMP_DIR}/META-INF/" "${TEMP_DIR}/org/"

  if [ -n "$USE_JAR" ]; then
    jar 2>/dev/null xf "$arch" "$file"
  else
    unzip 2>/dev/null -oq "$arch" "$file"
  fi

}

USER=$(whoami)
if [ "$USER" != "root" ];then
  echo 1>&2 "This script must be started with root privileges (id=$USER). Exit."
  exit 1
fi

echo -n '' > ${REPORT_DIR}/${REPORT_FILE}

UNZIP=$(command -v unzip)
JAR=$(command -v jar)
GREP=$(command -v grep)
PERL=$(command -v perl)

if [ -z $UNZIP ]; then
  if [ -z $JAR ]; then
    ERR="unzip/jar not found on the host."
    my_exit "$ERR"
  fi
  USE_JAR=1
fi

if [ -z $GREP ]; then
  ERR="grep not found on the host."
  my_exit "$ERR"
fi

if [ -z $PERL ]; then
  ERR="perl not found on the host."
  my_exit "$ERR"
fi

LOG4J_VULN_CLASS="JndiLookup.class"
LOG4J_V2_POM="META-INF/maven/org.apache.logging.log4j/log4j-core/pom.xml"
LOG4J_V1_POM="META-INF/maven/log4j/log4j/pom.xml"
LOG4J_V1_DTD="org/apache/log4j/xml/log4j.dtd"
LOG4J_V1_CLASS="org/apache/log4j/Logger.class"
LOG4J_V2_CLASS="org/apache/logging/log4j/Logger.class"

echo "Start log4j detector. This could take a while..."

for log4j_lib in `find 2>/dev/null / -type f -name "*.jar"`; do
  LOG4J_VERSION=''

  if [ -f "$log4j_lib" ]; then
    # Testing if it is V2 library
    findInArchive $LOG4J_V2_CLASS "$log4j_lib"
    MAJOR_VERSION_2=$fFile

    findInArchive $LOG4J_V1_CLASS "$log4j_lib"
    MAJOR_VERSION_1=$fFile

    findInArchive $LOG4J_VULN_CLASS "$log4j_lib"
    VULNERABLE_JAR=$(echo $fFile | perl -ne 'if ( m/([\w\/]+\w+\.class)/ ) { print $1; last}')

    if [ -z "$MAJOR_VERSION_1" ] && [ -z "$MAJOR_VERSION_2" ]; then
      continue
    fi

     # Trying to find log4j version in MANIFEST file
    extractFile "META-INF/MANIFEST.MF" "$log4j_lib"
    LOG4J_VERSION=$(cat 2>/dev/null "${TEMP_DIR}/META-INF/MANIFEST.MF" | perl -ne 's/[\r\n\ ]//g; $pom .= $_; if ( $pom =~ m/Manifest-version.*log4j.*-Version\:([\d\.]+)/i ) { print $1; last; }')


    if [ -z "$LOG4J_VERSION" ] && [ -n "$MAJOR_VERSION_2" ]; then
      # Trying to find log4j version in pom.xml file
      extractFile $LOG4J_V2_POM "$log4j_lib"  
      LOG4J_VERSION=$(cat 2>/dev/null "${TEMP_DIR}/${LOG4J_V2_POM}" | perl -ne 's/[\r\n\ ]//g; $pom .= $_; if ( $pom =~ m/<artifactId>log4j<\/artifactId>.*<version>(.+?)<\/version>/ ) { print $1; last; }')  
    fi

    if [ -z "$LOG4J_VERSION" ] && [ -n "$MAJOR_VERSION_1" ]; then
      # Trying to find log4j version in pom.xml file
      extractFile "$LOG4J_V1_POM" "$log4j_lib"
      LOG4J_VERSION=$(cat 2>/dev/null "${TEMP_DIR}/$LOG4J_V1_POM" | perl -ne 's/[\r\n\ ]//g; $pom .= $_; if ( $pom =~ m/<artifactId>log4j<\/artifactId>.*<version>(.+?)<\/version>/ ) { print $1; last; }')

      if [ -z "$LOG4J_VERSION" ]; then 
        # Trying to find log4j version in log4j.dtd file
        extractFile "$LOG4J_V1_DTD" "$log4j_lib"
        LOG4J_VERSION=$(cat 2>/dev/null "${TEMP_DIR}/$LOG4J_V1_DTD" | perl -ne 'if ( m/Version:.*?([\d\.]+)/ ) { print $1; last}')
      fi
    fi

    echo -e "$HOST\t$log4j_lib\t$LOG4J_VERSION\t$VULNERABLE_JAR" >> ${REPORT_DIR}/${REPORT_FILE}

  fi

done

rm -rf "${TEMP_DIR}/META-INF/" "${TEMP_DIR}/org/"
echo "log4j scanning report saved to ${REPORT_DIR}/${REPORT_FILE}"

