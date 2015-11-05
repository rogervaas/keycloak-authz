module.factory('ResourceServer', function($resource) {
    return $resource(authUrl + '/admin/realms/:realm/authz/resource-server/:rsid', {
        realm : '@realm',
        rsid : '@rsid'
    }, {
        'update' : {method : 'PUT'},
        'settings' : {url: authUrl + '/admin/realms/:realm/authz/resource-server/:rsid/settings', method : 'GET'}
    });
});

module.factory('ResourceServerResource', function($resource) {
    return $resource(authUrl + '/admin/realms/:realm/authz/resource-server/:rsid/resource/:rsrid', {
        realm : '@realm',
        rsid : '@rsid',
        rsrid : '@rsrid'
    }, {
        'update' : {method : 'PUT'}
    });
});

module.factory('ResourceServerScope', function($resource) {
    return $resource(authUrl + '/admin/realms/:realm/authz/resource-server/:rsid/scope/:id', {
        realm : '@realm',
        rsid : '@rsid',
        id : '@id'
    }, {
        'update' : {method : 'PUT'}
    });
});

module.factory('ResourceServerPolicy', function($resource) {
    return $resource(authUrl + '/admin/realms/:realm/authz/resource-server/:rsid/policy/:id', {
        realm : '@realm',
        rsid : '@rsid',
        id : '@id'
    }, {
        'update' : {method : 'PUT'}
    });
});

module.factory('PolicyProvider', function($resource) {
    return $resource(authUrl + '/admin/realms/:realm/authz/resource-server/:rsid/policy/providers', {
        realm : '@realm',
        rsid : '@rsid'
    });
});

module.service('AuthzDialog', function($modal) {
    var dialog = {};

    var openDialog = function(title, message, btns, template) {
        var controller = function($scope, $modalInstance, $sce, title, message, btns) {
            $scope.title = title;
            $scope.message = $sce.trustAsHtml(message);
            $scope.btns = btns;

            $scope.ok = function () {
                $modalInstance.close();
            };
            $scope.cancel = function () {
                $modalInstance.dismiss('cancel');
            };
        };

        return $modal.open({
            templateUrl: resourceUrl + template,
            controller: controller,
            resolve: {
                title: function() {
                    return title;
                },
                message: function() {
                    return message;
                },
                btns: function() {
                    return btns;
                }
            }
        }).result;
    }

    dialog.confirmDeleteWithMsg = function(name, type, msg, success) {
        var title = 'Delete ' + type;
        msg += 'Are you sure you want to permanently delete the ' + type + ' <strong>' + name + '</strong> ?';
        var btns = {
            ok: {
                label: 'Delete',
                cssClass: 'btn btn-danger'
            },
            cancel: {
                label: 'Cancel',
                cssClass: 'btn btn-default'
            }
        }

        openDialog(title, msg, btns, '/templates/kc-authz-modal.html').then(success);
    };

    dialog.confirmDelete = function(name, type, success) {
        var title = 'Delete ' + type;
        var msg = 'Are you sure you want to permanently delete the ' + type + ' <strong>' + name + '</strong> ?';
        var btns = {
            ok: {
                label: 'Delete',
                cssClass: 'btn btn-danger'
            },
            cancel: {
                label: 'Cancel',
                cssClass: 'btn btn-default'
            }
        }

        openDialog(title, msg, btns, '/templates/kc-authz-modal.html').then(success);
    }

    return dialog;
});