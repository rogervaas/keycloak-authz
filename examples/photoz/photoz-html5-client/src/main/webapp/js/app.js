var module = angular.module('photoz', ['ngRoute', 'ngResource']);
var Identity = {};
angular.element(document).ready(function ($http) {
    var keycloakAuth = new Keycloak('keycloak.json');
    Identity.loggedIn = false;
    keycloakAuth.init({onLoad: 'login-required'}).success(function () {
        Identity.loggedIn = true;
        Identity.authz = keycloakAuth;
        Identity.logout = function () {
            Identity.loggedIn = false;
            Identity.claim = {};
            Identity.authc = null;
            window.location = this.authz.authServerUrl + "/realms/photoz/protocol/openid-connect/logout?redirect_uri=http://localhost:8080/photoz-html5-client/index.html";
            Identity.authz = null;
        };
        Identity.claim = {};
        Identity.claim.name = Identity.authz.idTokenParsed.name;
        Identity.hasRole = function (name) {
            if (Identity.authz && Identity.authz.realmAccess) {
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
    $scope.deleteAlbum = function (album) {
        var newAlbum = new Album(album);
        newAlbum.$delete({id: album.id}, function () {
            $route.reload();
        });
    }

    $scope.showRpt = function () {
        document.getElementById("output").innerHTML = JSON.stringify(jwt_decode(Identity.uma.rpt.rpt), null, '  ');
    }

    $scope.showAccessToken = function () {
        document.getElementById("output").innerHTML = JSON.stringify(jwt_decode(Identity.authc.token), null, '  ');
    }

    $scope.requestEntitlements = function () {
        var request = new XMLHttpRequest();

        request.open("GET", "http://localhost:8080/auth/realms/photoz/entitlement?resourceServerId=photoz-restful-api", true);
        request.setRequestHeader("Authorization", "Bearer " + Identity.authc.token);
        request.onreadystatechange = function () {
            if (request.readyState == 4 && request.status == 200) {
                Identity.uma.rpt = JSON.parse(request.responseText);
            }
        }

        request.send(null);
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
    $http.get('/photoz-restful-api/admin/album').success(function (data) {
        $scope.albums = data;
    }).error(function (data, status, headers, config) {
        console.log('An error occured, please check the console logs for full information. Status code: ' + status + ':' + data);
    });
    $scope.deleteAlbum = function (album) {
        var newAlbum = new Album(album);
        newAlbum.$delete({id: album.id}, function () {
            $route.reload();
        });
    }
});
module.factory('Album', ['$resource', function ($resource) {
    return $resource('http://localhost:8080/photoz-restful-api/album/:id');
}]);
module.factory('AdminAlbum', ['$resource', function ($resource) {
    return $resource('http://localhost:8080/photoz-restful-api/admin/album/:id');
}]);
module.factory('authInterceptor', function ($q, $injector, $timeout, Identity) {
    return {
        request: function (request) {
            if (Identity.uma && Identity.uma.rpt && request.url.indexOf('/album') != -1) {
                request.headers.Authorization = 'Bearer ' + Identity.uma.rpt.rpt;
            } else {
                request.headers.Authorization = 'Bearer ' + Identity.authc.token;
            }
            return request;
        },
        responseError: function (rejection) {
            var deferred = $q.defer(rejection);

            if (rejection.status === 403) {
                if (rejection.config.url.indexOf('/album') != -1) {
                    if (rejection.data.ticket) {
                        var data = JSON.stringify({
                            ticket: rejection.data.ticket,
                            rpt: Identity.uma ? Identity.uma.rpt.rpt : ""
                        });

                        console.log(data);

                        var $http = $injector.get("$http");

                        $http.post('http://localhost:8080/auth/realms/photoz/authz/authorize', data, {headers: {"Authorization": "Bearer " + Identity.authc.token}})
                            .then(function (authzResponse) {
                                if (authzResponse.data) {
                                    Identity.uma = {};
                                    Identity.uma.rpt = authzResponse.data;
                                    console.log("Received RPT");
                                    console.log(Identity.uma.rpt);
                                }
                            });

                        return $timeout(function () {
                            return $http(rejection.config).then(function (response) {
                                return response;
                            }, function () {
                                return $q.reject(rejection);
                            });
                        }, 2000);
                    }
                }
                return $q.reject(rejection);
            }

            /* If not a 401, do nothing with this error.
             * This is necessary to make a `responseError`
             * interceptor a no-op. */
            return $q.reject(rejection);
        }
    };
});
module.config(function ($httpProvider, $routeProvider) {
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