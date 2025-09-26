var app = angular.module('loginApp', []);
app.service('AuthService', function($q) {
  var validUser = { email: 'user@example.com', password: 'password123' };
this.login = function(user) {
    var deferred = $q.defer();
if(user.email === validUser.email&&user.password === validUser.password) {
deferred.resolve({ success: true });
    } else {
deferred.reject({ message: 'Invalid email or password' });
    }
    return deferred.promise;
  };
});
app.controller('LoginController', function($rootScope, AuthService) {
  var vm = this;
vm.user = {};
vm.errorMessage = '';
vm.login = function() {
AuthService.login(vm.user).then(function() {
      $rootScope.loggedInUser = vm.user.email;
localStorage.setItem('loggedInUser', vm.user.email);
alert('Login successful! Redirecting to dashboard...');
    }, function(error) {
vm.errorMessage = error.message;
    });
  };
});


