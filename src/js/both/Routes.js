Ext.define('Tualo.routes.ModSecurityLog', {
    statics: {
        load: async function () {
            return [
                {
                    name: 'ModSecurity Log',
                    path: '#modsecuritylog/panel'
                }
            ]
        }
    },
    url: 'modsecuritylog/panel',
    handler: {
        action: function () {
            try {
                let fn = async function () {
                    let result = await fetch('./modsecuritylog/access');
                    result = await result.json();
                    if (result.success) {
                        Ext.getApplication().addView('Tualo.modsecuritylog.lazy.Panel');
                    }
                }();
            } catch (e) {
                console.error(e);
            }
        },
        before: function (action) {
            // Ext.require('Tualo.modsecuritylog.lazy.Panel', function () {
            action.resume();
            // }, this);
        }
    }
});
