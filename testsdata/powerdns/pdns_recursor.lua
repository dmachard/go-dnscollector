protobufServer("127.0.0.1:6001", {
    logQueries=true,
    logResponses=true,
    exportTypes={'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SPF', 'SRV', 'TXT'}
})
