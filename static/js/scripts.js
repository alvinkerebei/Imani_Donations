$("form[name=signup_form").submit(function(e){

    var $form = $(this);
    var $error = $form.find(".error");
    var data  = $form.serializeArray(); //data object that gets all fields from form, funnels them and sends to backend(routes)

    $.ajax({
        url: "/donor/signup",
        type: "POST",
        data: JSON.stringify(formData),
        dataType: "json",
        success: function(resp){
            console.log(resp);
        },
        error: function(resp){
            console.log(resp);
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        }
    });

    e.preventDefault(); //to prevent from submiting to another page or the page itself '
});