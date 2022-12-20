FROM centos:7
RUN yum -y install java-11-openjdk-devel maven && yum clean all && rm -rf /var/cache/yum/*
RUN alternatives --set java $(alternatives --display java | grep 'family java-11-openjdk' | cut -d' ' -f1)
RUN alternatives --set javac $(alternatives --display javac | grep 'family java-11-openjdk' | cut -d' ' -f1)
RUN mkdir /build
