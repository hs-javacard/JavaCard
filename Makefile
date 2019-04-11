JC_HOME=java_card_kit-2_2_1

JC_PATH=${JC_HOME}/lib/apdutool.jar:${JC_HOME}/lib/apduio.jar:${JC_HOME}/lib/converter.jar:${JC_HOME}/lib/jcwde.jar:${JC_HOME}/lib/scriptgen.jar:${JC_HOME}/lib/offcardverifier.jar:${JC_HOME}/lib/api.jar:${JC_HOME}/lib/installer.jar:${JC_HOME}/lib/capdump.jar:${JC_HOME}/samples/classes:${CLASSPATH}

CONVERTER=java -Djc.home=${JC_HOME} -classpath ${JC_PATH}:CardApplet/bin com.sun.javacard.converter.Converter
GP=java -jar gp/gp.jar

all: applet terminal

applet: bin/CalcApplet.class bin/javacard/applet.cap

bin/javacard/applet.cap: bin/CalcApplet.class
	#Converting to cap file	
	${CONVERTER} -v -out CAP -exportpath ${JC_HOME}/api_export_files -classdir bin -d bin \
	-applet 0x12:0x34:0x56:0x78:0x90:0xAB applet.CalcApplet applet 0x12:0x34:0x56:0x78:0x90 1.0
	#Uninstall old applet
	${GP} --uninstall bin/applet/javacard/applet.cap
	#Installing applet
	${GP} --install bin/applet/javacard/applet.cap
	
bin/CalcApplet.class: src/applet/CalcApplet.java
	#Compiling CalcApplet
	javac -source 1.3 -target 1.1 -d bin -cp ${JC_PATH} src/applet/CalcApplet.java

clean:
	rm -rf bin/*
	${GP} --delete 0x12:0x34:0x56:0x78:0x90
