event http_reply(c: connection, version: string, code: count, reason: string)
{
	SumStats::observe("http response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
	
	if(code == 404)
	{
		SumStats::observe("404 response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
		SumStats::observe("unique 404 response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$host+c$http$uri));
	}
}

event zeek_init()
{
	local r1 = SumStats::Reducer($stream="http response", $apply=set(SumStats::SUM));
	local r2 = SumStats::Reducer($stream="404 response", $apply=set(SumStats::SUM));
	local r3 = SumStats::Reducer($stream="unique 404 response", $apply=set(SumStats::UNIQUE));
	
	SumStats::create([$name = "http scan",
                      $epoch = 10min,
                      $reducers = set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        	if("http response" in result && "404 response" in result && "unique 404 response" in result)
                                {
                        		local http_res_num :int = result["http response"]$num;
                        		local error_res_num :int = result["404 response"]$num;
                            		local unique_res_num :int = result["unique 404 response"]$unique;
                            	if(error_res_num>2 && error_res_num>0.2*http_res_num && unique_res_num/error_res_num>0.5)
                            	{
                            		print fmt("%s is the orig_h, %d is the count of 404 response , %d is the unique count of url response 404",
                            		         key$host,error_res_num,unique_res_num);
                            	}
                          	}
                            
                        
                        }]);
}
