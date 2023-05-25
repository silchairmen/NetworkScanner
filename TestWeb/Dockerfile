FROM ubuntu:20.04

# 환경 변수 설정
ENV DEBIAN_FRONTEND=noninteractive

# 패키지 업데이트 및 필수 패키지 설치
RUN apt-get update && apt-get install -y apache2 vsftpd

# Apache2 설정 파일 수정
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

RUN service httpd start && service vsftpd start

# 포트 열기
EXPOSE 80 21 22 23 443

# 컨테이너 시작 시 실행할 명령
CMD ["apache2ctl", "-D", "FOREGROUND"]