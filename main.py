"""
* 다음과 같이 실행되도록 모듈을 통합하여 구현
  (웹과 통합하여 네트워크ID 또는 IP 입력하면 공격이 되고 결과가 출력되도록 하면 더욱 좋음!)

1. 호스트 스캔 후 

2. 활성 상태에 있는 호스트에 대해 포트 스캔

3. 열려있는 서비스 별 공격

  (예)

   . ftp: 로그인, 파일 업로드, 다운로드(zip 파일이면 암호 풀기), 웹을 이용한 공격 등등..

   . SSH : 로그인 공격 등

   . telnet :  로그인 공격 등

   . 이메일 등등 공격….
"""
from src.view.app import *
from src.core.CustomFunc import *


if __name__ == '__main__':
    p_print("Starting Website")
    try:
        #app.run
        run()
    except Exception as e:
        e_print(F"Error! {e}")
