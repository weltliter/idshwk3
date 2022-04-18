global addr_agent_table : table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string){
	local http_ip : addr = c$id$orig_h;
	if(c$http?$user_agent){
		local addr_agent : string = c$http$user_agent;
		if(http_ip in addr_agent_table){
			add (addr_agent_table[http_ip])[addr_agent];
		}else{
			addr_agent_table[http_ip] = set(addr_agent);
		}
}


event zeek_done(){
	for(ip in addr_agent_table){
		if(|addr_agent_table[ip]| >= 3){
			print(cat(ip) + " is a proxy");
		}
	}
}