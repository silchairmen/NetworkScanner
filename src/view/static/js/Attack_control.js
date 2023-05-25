function performAction(ip, port, action) {
  // 로딩 창 표시
  $('#loading').modal('show');

  // AJAX 요청
  $.ajax({
    url: '/attackOptions',
    type: 'POST',
    data: { ip: ip, port: port, action: action },
    dataType: 'json',
    success: function(response) {
      // 로딩 창 숨기기
      $('#loading').modal('hide');

      // 응답 처리
      if (response['info']) {
        // Brouteforce 성공 시 id와 pw를 포함한 div를 생성하여 추가
        var resultDiv = '<div>Brouteforce 성공</div>';
        resultDiv += '<div>id: ' + response["info"][0] + '</div>';
        resultDiv += '<div>pw:' + response["info"][1] + '</div>';

      } else if (response['message'] === 'Fail') {
        // Brouteforce 실패 시 실패 메시지를 포함한 div를 생성하여 추가
        var resultDiv = '<div>Brouteforce 실패</div>';

      } else if (response['scan'] === 'success') {
        // Brouteforce 실패 시 실패 메시지를 포함한 div를 생성하여 추가
        var resultDiv = '<div>Annonymous 스캔 성공</div>';

      }
      else {
        var resultDiv = `<div>명령 수행 실패 ${response['error']}</div>`
      }
      $(`#${port}`).append(resultDiv);
    },
    error: function() {
      // 로딩 창 숨기기
      $('#loading').modal('hide');

      // 에러 처리
      var errorDiv = '<div>요청 처리 중 오류가 발생했습니다.</div>';
      $(`#${port}`).append(errorDiv);
    }
  });
}