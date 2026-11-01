import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dns from "node:dns/promises";
import net from "node:net";
const app=express(),root=path.dirname(fileURLToPath(import.meta.url));
app.disable("x-powered-by");
app.use(express.json({limit:"32kb"}));
app.use(express.static(path.join(root,"public"),{index:"index.html"}));
function privateIp(ip){
 if(net.isIP(ip)===4){const p=ip.split(".").map(Number);return p[0]===0||p[0]===10||p[0]===127||(p[0]===169&&p[1]===254)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||p[0]>=224;}
 if(net.isIP(ip)===6){const x=ip.toLowerCase();return x==="::"||x==="::1"||x.startsWith("fc")||x.startsWith("fd")||x.startsWith("fe80:");}
 return true;
}
async function validate(raw){
 const u=new URL(raw);
 if(u.protocol!=="https:"||u.username||u.password||(u.port&&u.port!=="443"))throw Error("Only public HTTPS URLs on port 443 are supported.");
 const h=u.hostname.toLowerCase();
 if(h==="localhost"||h.endsWith(".localhost"))throw Error("Local hosts are blocked.");
 if(net.isIP(h)){if(privateIp(h))throw Error("Private IPs are blocked.");}
 else{const rr=await dns.lookup(h,{all:true});if(!rr.length||rr.some(r=>privateIp(r.address)))throw Error("Host must resolve to public IP addresses.");}
 return u;
}
async function fetchText(start){
 let current=start;
 for(let hop=0;hop<4;hop++){
  await validate(current);const c=new AbortController(),t=setTimeout(()=>c.abort(),12000);let r;
  try{r=await fetch(current,{redirect:"manual",signal:c.signal,headers:{"User-Agent":"PURE-LOADSTRING-PRO/2.0","Accept":"text/plain, application/javascript, */*"}});}finally{clearTimeout(t);}
  if([301,302,303,307,308].includes(r.status)){const loc=r.headers.get("location");if(!loc)throw Error("Redirect has no location.");current=new URL(loc,current).toString();continue;}
  if(!r.ok)throw Error("Remote server returned HTTP "+r.status+".");
  const source=await r.text();if(Buffer.byteLength(source)>1000000)throw Error("Response exceeds 1 MB.");if(!source.trim())throw Error("Empty response.");
  return {source,finalUrl:current,contentType:r.headers.get("content-type")||"unknown",bytes:Buffer.byteLength(source)};
 }
 throw Error("Too many redirects.");
}
app.get("/api/health",(_q,s)=>s.json({ok:true,version:"2.0.0"}));
app.post("/api/fetch",async(req,res)=>{try{
 const input=String(req.body?.url||"").trim();if(!input)throw Error("Paste a loadstring or HTTPS URL.");
 const m=input.match(/(?:HttpGet|httpget|HttpGetAsync|httpgetasync)\s*\(\s*["'](https:\/\/[^"'\s]+)["']\s*\)/i);
 const target=/^https:\/\/\S+$/i.test(input)?input:m?.[1];if(!target)throw Error("No direct HTTPS URL found in the input.");
 res.json(await fetchText(target));
}catch(e){res.status(400).json({error:e.name==="AbortError"?"Remote request timed out.":e.message||"Fetch failed."});}});
app.listen(process.env.PORT||3000,"0.0.0.0",()=>console.log("PURE LOADSTRING PRO started"));
