async function doLogin(){
  const pw=document.getElementById('lPw').value;
  const err=document.getElementById('lErr');
  err.textContent='';
  if(!pw){err.textContent='Please enter a password.';return;}
  try{
    const r=await fetch('/api/login',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pw})});
    const d=await r.json();
    if(d.ok){
      const next=new URLSearchParams(window.location.search).get('next')||'/';
      window.location.href=next;
    }else{
      err.textContent=d.error||'Incorrect password.';
      document.getElementById('lPw').select();
    }
  }catch(e){err.textContent='Network error: '+e;}
}
// Apply saved theme
function updateFavicon(theme){
  var filters={
    dark:'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    black:'hue-rotate(330deg) saturate(1.1) brightness(0.75)',
    light:'grayscale(1) brightness(0.5)',
    midnight:'hue-rotate(182deg) saturate(1.1)',
    dracula:'hue-rotate(238deg) saturate(1.2)',
    terminal:'hue-rotate(118deg) saturate(1.2)',
    ocean:'hue-rotate(178deg) saturate(1.2)',
    sunset:'hue-rotate(6deg) saturate(1.2)',
    forest:'hue-rotate(118deg) saturate(1.2)',
    purple:'hue-rotate(248deg) saturate(1.2)',
    neon:'hue-rotate(166deg) saturate(1.2)',
    rose:'hue-rotate(334deg) saturate(1.1)',
    amber:'hue-rotate(20deg) saturate(1.2)',
    solarized:'hue-rotate(162deg) saturate(0.9)'
  };
  var src=document.getElementById('sticks');
  var link=document.querySelector("link[rel='icon']");
  if(!src||!link)return;
  var c=document.createElement('canvas');
  c.width=c.height=32;
  var ctx=c.getContext('2d');
  ctx.filter=filters[theme]||filters.black;
  ctx.drawImage(src,0,0,32,32);
  link.href=c.toDataURL();
}
fetch('/api/webui/settings').then(r=>r.json()).then(s=>{
  if(s&&s.theme){
    document.documentElement.setAttribute('data-theme',s.theme);
    updateFavicon(s.theme);
  }
}).catch(()=>{});
// Show version badge
fetch('/api/version').then(r=>r.json()).then(d=>{
  if(d.version&&d.version!=='unknown'){
    const b=document.getElementById('lVer');
    if(b){b.textContent='v'+d.version;b.style.display='';}
  }
}).catch(()=>{});
