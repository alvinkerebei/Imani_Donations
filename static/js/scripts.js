$("form[name=signup_form").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();
  
    $.ajax({
      url: "/donor/signup",
      type: "POST",
      data: data,
      dataType: "json",
      success: function(resp) {
        window.location.href = "/donordash/";
      },
      error: function(resp) {
        $error.text(resp.responseJSON.error).removeClass("error--hidden");
      }
    });
  
    e.preventDefault();
  });
  
  $("form[name=login_form").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();
  
    $.ajax({
      url: "/donor/login",
      type: "POST",
      data: data,
      dataType: "json",
      success: function(resp) {
        window.location.href = "/donordash/";
      },
      error: function(resp) {
        $error.text(resp.responseJSON.error).removeClass("error--hidden");
      }
    });
  
    e.preventDefault();
  });

  $("form[name=resetpass_form").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();
  
    $.ajax({
      url: "/donor/reset_pass",
      type: "POST",
      data: data,
      dataType: "json",
      success: function(resp) {
        window.location.href = "/reset_pass/";
      },
      error: function(resp) {
        $error.text(resp.responseJSON.error).removeClass("error--hidden");
      }
    });
  
    e.preventDefault();
  });