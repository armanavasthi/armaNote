$(document).ready(function(){
	var url = "/webservice/user/";
	$.get(url).then(function(res, textStatus, request){
		console.log(res)
		if(res.success){
			console.log("yipeeee")
		}
	})

})