Ext.define('Tualo.modsecuritylog.Loader', {
    singleton: true,

    constructor: function () {
        Ext.Loader.setPath('Tualo.modsecuritylog.lazy', './js/modsecuritylog/lazy');
    }
});
