var module = angular.module('photoz', ['ngRoute', 'ngResource']);
var Identity = {};
angular.element(document).ready(function ($http) {
    var keycloakAuth = new Keycloak('keycloak.json');
    Identity.loggedIn = false;
    keycloakAuth.init({onLoad: 'login-required'}).success(function () {
        Identity.loggedIn = true;
        Identity.authz = keycloakAuth;
        Identity.logout = function () {
            console.log('*** LOGOUT');
            Identity.loggedIn = false;
            Identity.claim = {};
            Identity.authc = null;
            window.location = this.authz.authServerUrl + "/realms/photoz/tokens/logout?redirect_uri=http://localhost:9080/photoz-html5-client/index.html";
            Identity.authz = null;
        };
        Identity.claim = {};
        Identity.claim.name = Identity.authz.idTokenParsed.name;
        Identity.hasRole = function (name) {
            if (Identity.authz.realmAccess) {
                for (role of Identity.authz.realmAccess.roles) {
                    if (role == name) {
                        return true;
                    }
                }
            }
            return false;
        };
        Identity.isAdmin = function () {
            return this.hasRole("admin");
        };
        Identity.authc = {};
        Identity.authc.token = Identity.authz.token;
        module.factory('Identity', function () {
            return Identity;
        });
        angular.bootstrap(document, ["photoz"]);
    }).error(function () {
        window.location.reload();
    });
});
module.controller('GlobalCtrl', function ($scope, $http, $route, $location, Album, Identity) {
    $scope.Identity = Identity;
    Album.query(function (albums) {
        $scope.albums = albums;
    });
    $scope.deleteAlbum = function(album) {
        var newAlbum = new Album(album);
        newAlbum.$delete({id : album.id}, function () {
            $route.reload();
        });
    }
});
module.controller('AlbumCtrl', function ($scope, $http, $routeParams, $location, Album) {
    $scope.album = {};
    if ($routeParams.id) {
        $scope.album = Album.get({id: $routeParams.id});
    }
    $scope.create = function () {
        var newAlbum = new Album($scope.album);
        newAlbum.$save({}, function (data) {
            $location.path('/');
        });
    };
});
module.controller('AdminAlbumCtrl', function ($scope, $http, $route, AdminAlbum, Album) {
    $scope.albums = {};
    $http.get('/photoz-restful-api/admin/album').success(function(data) {
        $scope.albums = data;
        console.log(data);
    }).error(function(data, status, headers, config) {
        console.log('An error occured, please check the console logs for full information. Status code: ' + status+':'+data);
    });
    $scope.deleteAlbum = function(album) {
        var newAlbum = new Album(album);
        newAlbum.$delete({id : album.id}, function () {
            $route.reload();
        });
    }
});
module.factory('Album', ['$resource', function ($resource) {
    return $resource('http://localhost:9080/photoz-restful-api/album/:id');
}]);
module.factory('AdminAlbum', ['$resource', function ($resource) {
    return $resource('http://localhost:9080/photoz-restful-api/admin/album/:id');
}]);
module.factory('authInterceptor', function ($q, Identity) {
    return {
        request: function (config) {
            var deferred = $q.defer();
            if (Identity.authc.token) {
                Identity.authz.updateToken(5).success(function () {
                    config.headers = config.headers || {};

                    if (Identity.uma && Identity.uma.rpt) {
                        console.log("Sending rpt");
                        config.headers.Authorization = 'Bearer ' + Identity.uma.rpt.rpt;
                    } else {
                        console.log("Sending at");
                        config.headers.Authorization = 'Bearer ' + Identity.authc.token;
                    }

                    deferred.resolve(config);
                }).error(function () {
                    deferred.reject('Failed to refresh token');
                });
            }
            return deferred.promise;
        }
    };
});
module.config(function ($httpProvider, $routeProvider) {
    $httpProvider.responseInterceptors.push('errorInterceptor');
    $httpProvider.interceptors.push('authInterceptor');
    $routeProvider.when('/', {
        templateUrl: 'partials/home.html',
        controller: 'GlobalCtrl',
        isFree: false
    }).when('/album/create', {
        templateUrl: 'partials/album/create.html',
        controller: 'AlbumCtrl',
    }).when('/album/:id', {
        templateUrl: 'partials/album/detail.html',
        controller: 'AlbumCtrl',
    }).when('/admin/album', {
        templateUrl: 'partials/admin/albums.html',
        controller: 'AdminAlbumCtrl',
    }).otherwise({
        redirectTo: '/'
    });
});
module.factory('errorInterceptor', function ($q, $injector) {
    return function (promise) {
        return promise.then(function (response) {
            return response;
        }, function (response) {
            if (response.status == 401) {
                console.log('session timeout?');
                logout();
            } else if (response.status == 403) {
                console.log("Forbidden");
                Identity.uma = null;

                var authenticateHeader = response.headers("WWW-Authenticate");

                if (authenticateHeader) {
                    var deferred = $q.defer();

                    //var properties = authenticateHeader.split(",");
                    //
                    //for (p of properties) {
                    //    p = p.trim();
                    //    var idx = p.indexOf("as_uri=\"");
                    //
                    //    if (idx == 0) {
                    //        var authzEndpoint = p.substring(idx + "as_uri=\"".length, p.length - 2);
                    //        console.log($http);
                    //    }
                    //}

                    var data = JSON.stringify({
                        ticket: response.data.ticket
                    });

                    $injector.get("$http").post('http://localhost:8080/auth/realms/photoz/authz/authorize', data, {headers: {"Authorization": "Bearer " + Identity.authc.token}})
                            .then(function(authzResponse) {
                                if (authzResponse.data) {
                                    Identity.uma = {};
                                    Identity.uma.rpt = authzResponse.data;
                                    // now let's retry the original request - transformRequest in .run() below will add the new OAuth token
                                    $injector.get("$http")(response.config).then(function(response) {
                                        // we have a successful response - resolve it using deferred
                                        deferred.resolve(response);
                                    },function(response) {
                                        deferred.reject();
                                        // something went wrong
                                    });
                                } else {
                                    deferred.reject(); // login.json didn't give us data
                                }
                            }, function(response) {
                                deferred.reject(); // token retry failed, redirect so user can login again
                                alert('Oops, you are probably missing some permission. Contact the administrator.');
                                return;
                            });
                    return deferred.promise;
                }
            } else if (response.status == 404) {
                alert("Not found");
            } else if (response.status) {
                if (response.data && response.data.errorMessage) {
                    alert(response.data.errorMessage);
                } else {
                    alert("An unexpected server error has occurred");
                }
            }
            return $q.reject(response);
        });
    };
});
