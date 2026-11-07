Ext.define('Tualo.modsecuritylog.lazy.Panel', {
    extend: 'Ext.panel.Panel',
    alias: 'widget.tualo_modsecuritylog_panel',

    requires: [
        'Tualo.modsecuritylog.lazy.controller.Panel',
        'Tualo.modsecuritylog.lazy.models.Panel'
    ],
    controller: 'tualo_modsecuritylog_panel',
    viewModel: {
        type: 'tualo_modsecuritylog_panel'
    },
    listeners: {
        boxready: 'onBoxReady'
    },
    title: 'ModSecurity Log',
    closable: true,
    layout: 'border',
    items: [
        {
            region: 'center',
            xtype: 'grid',
            itemId: 'entries',
            plugins: {
                gridfilters: true
            },
            tbar: [
                {
                    text: 'Aktualisieren',
                    iconCls: 'x-fa fa-sync',
                    handler: 'onRefresh'
                },
                {
                    xtype: 'textfield',
                    emptyText: 'Filter (URI, IP, Host, Regel-ID) ...',
                    width: 280,
                    listeners: {
                        change: {
                            fn: 'onFilterChange',
                            buffer: 300
                        }
                    }
                },
                '->',
                {
                    xtype: 'tbtext',
                    bind: {
                        text: '{logfile}'
                    }
                }
            ],
            columns: [
                { text: 'Zeit', dataIndex: 'timestamp', width: 150 },
                { text: 'Client', dataIndex: 'client_ip', width: 120 },
                { text: 'Methode', dataIndex: 'method', width: 80 },
                {
                    text: 'Status', dataIndex: 'status', width: 70,
                    renderer: function (value) {
                        if (Ext.isEmpty(value)) return '';
                        if (value >= 400) {
                            return '<span style="color:#c0392b;font-weight:bold;">' + value + '</span>';
                        }
                        return value;
                    }
                },
                {
                    text: 'Blockiert', dataIndex: 'intercepted', width: 85,
                    filter: { type: 'boolean' },
                    renderer: function (value) {
                        return value
                            ? '<span style="color:#c0392b;font-weight:bold;">ja</span>'
                            : 'nein';
                    }
                },
                { text: 'Score', dataIndex: 'inbound_score', width: 65 },
                { text: 'Severity', dataIndex: 'max_severity', width: 95, filter: { type: 'string' } },
                { text: 'URI', dataIndex: 'uri', flex: 1, filter: { type: 'string' } },
                { text: 'Host', dataIndex: 'host', width: 160, filter: { type: 'string' } },
                {
                    text: 'Regeln', dataIndex: 'rule_ids', width: 140,
                    renderer: function (value) {
                        return Ext.isArray(value) ? value.join(', ') : '';
                    }
                }
            ],
            bind: {
                store: '{entries}'
            },
            listeners: {
                selectionchange: 'onSelectionChange'
            }
        },
        {
            region: 'south',
            split: true,
            height: 260,
            title: 'Details',
            collapsible: true,
            scrollable: true,
            bind: {
                html: '{detailHtml}'
            }
        }
    ]
});
