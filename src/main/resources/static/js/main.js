$(document).ready(function(){

	$('form').submit(function(e){e.preventDefault()});
	
	$('#input-url').keypress(function(e){
		//var urlRegex = "/^$/";
		var fedUrl = $('#input-url').val();
		if (e.which == 13) {
			$('#urlButton').attr('href', fedUrl);
			$('#urlButton')[0].click();
			// first match the url regex if failed => return
		}
	})
	$('#urlButton').click(function() {
		if ($(this).attr('href')) {
			$(this).show();
			$('#iframeView').show();
		}
	})

})