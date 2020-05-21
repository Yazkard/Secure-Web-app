document.addEventListener('DOMContentLoaded', function (event) {
  console.log("Here!");
});


function submitUser() {
  var xhr = new XMLHttpRequest();
  xhr.withCredentials = true;

  xhr.addEventListener("readystatechange", function () {
    if (this.readyState == 4 && this.status == 400) {
      alert("Błąd podczas rejstracji");
    }
    if (this.readyState == 4 && this.status == 201) {
      window.location.assign('https://localhost:80')
    }
  });
  if (document.getElementById('password').value == document.getElementById('repeat-password').value) {
    var data = new FormData();
    data.append("password", document.getElementById('password').value);
    data.append("login", document.getElementById('login').value);
    xhr.open("POST", "https://localhost:80/register");
    xhr.send(data);
  } else {
    alert("hasła nie są identyczne")
  }
}

function LoginUser() {
  var xhr = new XMLHttpRequest();
  xhr.withCredentials = true;
  xhr.addEventListener("readystatechange", function () {
    if (this.readyState == 4 && this.status == 400) {
      window.location.assign('https://localhost:80/')
    }
    if (this.readyState == 4 && this.status == 200) {
      window.location.assign('https://localhost:81/')
    }
  });
  var data = new FormData();
  data.append("password", document.getElementById('password').value);
  data.append("login", document.getElementById('login').value);
  xhr.open("POST", "https://localhost:80/login");
  xhr.send(data);
}

function changePass() {
  var xhr = new XMLHttpRequest();
  xhr.withCredentials = true;

  xhr.addEventListener("readystatechange", function () {
    if (this.readyState == 4 && this.status == 400) {
      alert("Błąd podczas zmiany hasła");
    }
    if (this.readyState == 4 && this.status == 201) {
      window.location.assign('https://localhost:80')
    }
  });
  if (document.getElementById('password').value == document.getElementById('repeat-password').value) {
    var data = new FormData();
    data.append("password", document.getElementById('old_password').value);
    data.append("new_password", document.getElementById('password').value);
    data.append("new_password2", document.getElementById('repeat-password').value);
    data.append('csrf_token', document.getElementById('token').value);
    xhr.open("POST", "https://localhost:80/change_pass");
    xhr.send(data);
  } else {
    alert("hasła nie są identyczne")
  }
}