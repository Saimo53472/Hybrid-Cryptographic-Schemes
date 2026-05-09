# Hybrid-Cryptographic-Schemes

## Commands
To use jdk17:
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
export PATH=$JAVA_HOME/bin:$PATH

To use the Java card development kit:
export JC_HOME=~/Downloads/java_card_devkit_tools-bin-v25.1-b_611-26-OCT-2025
export PATH=$JC_HOME/bin:$PATH

To convert to class:
javac -source 8 -target 8 -classpath $JC_HOME/lib/api_classic-3.0.5.jar Chameleon/ChameleonApplet.java 

To convert to cap: 
$JC_HOME/bin/converter.sh -classdir . -applet 0xa0:0x00:0x00:0x00:0x00:0x00:0x01 ChameleonApplet Chameleon 0xa0:0x00:0x00:0x00:0x00:0x00 1.0