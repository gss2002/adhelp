FROM maven:3-amazoncorretto-21-al2023 as maven
LABEL APPLICATION="adhelp"
LABEL stage=auto-clean
WORKDIR /usr/src/app
COPY . /usr/src/app
RUN mvn package
FROM tomcat:11-jdk21
ENV CATALINA_OPTS="-Xms1024m -Xmx4096m -XX:MetaspaceSize=512m -XX:MaxMetaspaceSize=512m -Xss512k"
#Move over the War file from previous build step
WORKDIR /usr/local/tomcat/bin/
COPY java_env .
RUN /usr/bin/sed '1 a . /usr/local/tomcat/bin/java_env' -i catalina.sh
COPY src/main/resources/log4j2.properties /usr/local/tomcat/conf/
RUN update-ca-certificates
#RUN cp -rp /usr/local/tomcat/webapps.dist/ROOT /usr/local/tomcat/webapps/
#RUN echo "<% response.sendRedirect(\"/adhelp/\"); %>" > /usr/local/tomcat/webapps/ROOT/index.jsp
WORKDIR /usr/local/tomcat/conf/
RUN /usr/bin/sed '/<\/Host>/i\.       <Valve className="org.apache.catalina.valves.HealthCheckValve" path="\/healthz" \/>' -i server.xml
RUN /usr/bin/sed 's;org.apache.catalina.valves.AccessLogValve" directory="logs;org.apache.catalina.valves.AccessLogValve" directory="/dev/stdout;g' -i server.xml
RUN /usr/bin/sed 's;prefix="localhost_access_log" suffix=".txt";prefix="" suffix="" rotatable="false";g' -i server.xml
RUN groupadd -g 1001 tomcat && useradd -u 1001 -g 1001 tomcat
WORKDIR /usr/local/tomcat/webapps/
COPY --from=maven /usr/src/app/target/adhelp.war /usr/local/tomcat/webapps/adhelp.war
RUN chown -R tomcat:tomcat /usr/local/tomcat/webapps
USER tomcat
WORKDIR /usr/local/tomcat/bin
EXPOSE 8080
ENTRYPOINT ["catalina.sh", "run"]
