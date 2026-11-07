Ext.define('Tualo.modsecuritylog.lazy.controller.Panel', {
    extend: 'Ext.app.ViewController',
    alias: 'controller.tualo_modsecuritylog_panel',

    onBoxReady: function () {
        this.loadEntries();
    },

    loadEntries: function () {
        let me = this,
            model = me.getViewModel(),
            store = model.getStore('entries'),
            view = me.getView();

        view.setLoading(true);
        model.set('selectedEntry', null);
        store.load({
            params: {
                limit: model.get('limit')
            },
            callback: function (records, operation, success) {
                view.setLoading(false);
                if (!success) {
                    let msg = 'Fehler beim Laden des Audit-Logs.';
                    try {
                        let response = Ext.decode(operation.getError().response.responseText);
                        if (response.msg) msg = response.msg;
                    } catch (e) {
                        // Standardmeldung verwenden
                    }
                    Ext.Msg.alert('ModSecurity Log', msg);
                } else {
                    let raw = store.getProxy().getReader().rawData;
                    if (raw) {
                        if (raw.success === false) {
                            Ext.Msg.alert('ModSecurity Log', raw.msg || 'Fehler beim Lesen des Audit-Logs.');
                        }
                        if (raw.logfile) {
                            model.set('logfile', raw.logfile);
                        }
                    }
                }
            }
        });
    },

    onRefresh: function () {
        this.loadEntries();
    },

    onSelectionChange: function (grid, selected) {
        this.getViewModel().set('selectedEntry', selected.length > 0 ? selected[0] : null);
    },

    onFilterChange: function (field) {
        let store = this.getViewModel().getStore('entries'),
            value = (field.getValue() || '').toLowerCase();

        store.clearFilter();
        if (value !== '') {
            store.filterBy(function (record) {
                let haystack = [
                    record.get('uri'),
                    record.get('client_ip'),
                    record.get('host'),
                    record.get('method'),
                    (record.get('rule_ids') || []).join(' ')
                ].join(' ').toLowerCase();
                return haystack.indexOf(value) !== -1;
            });
        }
    }
});
