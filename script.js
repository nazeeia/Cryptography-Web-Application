const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const hx=n=>n.toString(16).padStart(2,'0').toUpperCase();
const bits=n=>'<span class="bits">'+n.toString(2).padStart(8,'0').split('').map(c=>`<i class="b${c}">${c}</i>`).join('')+'</span>';
const pr=c=>c>=32&&c<=126?String.fromCharCode(c):'·';
const bytes=s=>[...s].map(c=>c.charCodeAt(0));
const toHex=a=>a.map(hx).join('');
const xor=(a,k)=>a.map((b,i)=>b^k[i%k.length]);
const err=(el,t)=>{el.innerHTML=`<div class="msg er">❌ Error: ${esc(t)}</div>`};

function chk(s,n){
  if(!s)return `${n} masih kosong. Silakan isi ${n}.`;
  for(const c of s){const x=c.charCodeAt(0);if(x<32||x>126)return `${n} berisi karakter yang tidak didukung ("${c}"). Gunakan ASCII cetak 32–126: huruf, angka, simbol, dan spasi.`}
  return '';
}
function lenErr(n,k){return $('mode').value==='otp'&&k<n?`Mode OTP: kunci (${k} karakter) harus minimal sama panjang dengan pesan (${n}). Perpanjang kunci atau pindah ke mode Stream cipher.`:''}
function hexParse(s){
  const t=s.replace(/\s+/g,'');
  if(!t)return{e:'Ciphertext masih kosong. Tempel ciphertext dalam format hex.'};
  if(!/^[0-9a-f]+$/i.test(t))return{e:'Format ciphertext salah. Gunakan hanya angka 0–9 dan huruf A–F, contoh: 3A0F1C.'};
  if(t.length%2)return{e:'Jumlah digit hex ganjil. Setiap byte terdiri dari 2 digit hex.'};
  return{b:t.match(/../g).map(h=>parseInt(h,16))};
}
function viz(inp,kb,out,l1,l2){
  const n=Math.min(inp.length,24);
  let h=`<table><thead><tr><th>#</th><th>${l1}</th><th>Bit ${l1}</th><th>Kunci</th><th>Bit kunci</th><th>Bit hasil (XOR)</th><th>${l2}</th></tr></thead><tbody>`;
  for(let i=0;i<n;i++){const k=kb[i%kb.length];
    h+=`<tr><td>${i+1}</td><td class="m">${esc(pr(inp[i]))} <small>${hx(inp[i])}</small></td><td>${bits(inp[i])}</td><td class="m">${esc(pr(k))}</td><td>${bits(k)}</td><td><span class="bits x">${bits(out[i])}</span></td><td class="m">${hx(out[i])} <small>${esc(pr(out[i]))}</small></td></tr>`}
  return h+'</tbody></table>'+(inp.length>n?`<p class="mu">Menampilkan ${n} dari ${inp.length} karakter pertama.</p>`:'');
}

/* Tabs */
document.querySelectorAll('#tabs button').forEach(b=>b.onclick=()=>show(b.dataset.t));
function show(t){
  document.querySelectorAll('#tabs button').forEach(b=>b.setAttribute('aria-selected',b.dataset.t===t));
  document.querySelectorAll('.pane').forEach(p=>p.classList.toggle('on',p.id===t));
}

/* OTP state */
let genFlag=false,last=null;const used=new Map();
$('k1').addEventListener('input',()=>{genFlag=false});
$('gen').onclick=()=>{
  const n=Math.max($('pt').value.length,8),r=new Uint8Array(n);crypto.getRandomValues(r);
  $('k1').value=[...r].map(x=>String.fromCharCode(33+x%94)).join('');genFlag=true;
};

/* Enkripsi */
let lastCt='',lastKey='';
$('be').onclick=()=>{
  const p=$('pt').value,k=$('k1').value,o=$('o1');
  const e=chk(p,'Plaintext')||chk(k,'Kunci')||lenErr(p.length,k.length);
  if(e){err(o,e);$('v1').innerHTML='';return}
  const pb=bytes(p),kb=bytes(k),cb=xor(pb,kb);lastCt=toHex(cb);lastKey=k;
  const reuse=used.has(k)&&used.get(k)!==p;used.set(k,p);
  last={rand:genFlag,len:k.length>=p.length,n:p.length,kl:k.length,reuse};
  o.innerHTML=`<div class="flow"><span>${esc(p)}</span><i>⊕</i><span>${esc(k)}</span><i>→</i><span>${lastCt}</span></div>
  <div class="res"><small>Ciphertext (hex)</small><code>${lastCt}</code></div>`+
  (k.length<p.length?`<div class="msg wa">⚠️ Kunci (${k.length}) lebih pendek dari pesan (${p.length}), jadi keystream berulang. Pola berulang ini mudah diserang.</div>`:'')+
  (reuse?`<div class="msg wa">⚠️ Kunci ini sudah dipakai untuk pesan lain. Lihat tab Serangan.</div>`:'');
  $('v1').innerHTML=viz(pb,kb,cb,'Plaintext','Ciphertext');otpRender();
};
$('send').onclick=()=>{
  if(!lastCt){err($('o1'),'Belum ada ciphertext. Klik “Enkripsi” terlebih dahulu.');return}
  $('ct').value=lastCt;$('k2').value=lastKey;show('dec');
};

/* Dekripsi */
$('bd').onclick=()=>{
  const c=hexParse($('ct').value),k=$('k2').value,o=$('o2');
  const e=c.e||chk(k,'Kunci')||lenErr(c.b.length,k.length);
  if(e){err(o,e);$('v2').innerHTML='';return}
  const kb=bytes(k),pb=xor(c.b,kb),bad=pb.some(x=>x<32||x>126);
  o.innerHTML=`<div class="flow"><span>${toHex(c.b)}</span><i>⊕</i><span>${esc(k)}</span><i>→</i><span>${esc(pb.map(pr).join(''))}</span></div>
  <div class="res"><small>Plaintext</small><code>${esc(pb.map(pr).join(''))}</code></div>`+
  (bad?`<div class="msg wa">⚠️ Ada byte yang bukan karakter cetak (ditampilkan sebagai ·). Kunci kemungkinan salah.</div>`:'');
  $('v2').innerHTML=viz(c.b,kb,pb,'Ciphertext','Plaintext');
};

/* Test case */
const T=[
 {p:'CAT',k:'KEY',x:'08040D'},
 {p:'Hi!',k:'xyz',x:'30105B'},
 {p:'OTP',k:'Zq9',x:'152569'},
 {p:'ATTACK',k:'AB',x:'001615030209'}];
function runTests(){
  const btn=$('bt');btn.disabled=true;btn.textContent='Menjalankan…';
  $('tb').innerHTML='';$('tsum').innerHTML='';
  let ok=0;
  T.forEach((t,i)=>setTimeout(()=>{
    const out=toHex(xor(bytes(t.p),bytes(t.k)));
    const back=xor(t.x.match(/../g).map(h=>parseInt(h,16)),bytes(t.k)).map(pr).join('');
    const pass=out===t.x&&back===t.p;if(pass)ok++;
    $('tb').insertAdjacentHTML('beforeend',`<tr><td>${i+1}</td><td class="m">P: ${esc(t.p)}<br>K: ${esc(t.k)}</td><td>ASCII → XOR<br>tiap byte kunci</td><td class="m">${out}</td><td class="m">${t.x}</td><td><span class="${pass?'pass':'fail'}">${pass?'PASS':'FAIL'}</span></td></tr>`);
    if(i===T.length-1){
      $('tsum').innerHTML=`<div class="msg ${ok===T.length?'ok':'er'}">${ok===T.length?'✅':'❌'} ${ok} dari ${T.length} test case lulus.</div>`;
      btn.disabled=false;btn.textContent='Jalankan ulang';
    }
  },500*(i+1)));
}
$('bt').onclick=runTests;

/* Serangan */
let X=null;
$('ba').onclick=()=>{
  const m1=$('m1').value,m2=$('m2').value,k=$('ka').value,o=$('oa');
  const e=chk(m1,'Pesan 1')||chk(m2,'Pesan 2')||chk(k,'Kunci');
  if(e){err(o,e);X=null;return}
  const n=Math.min(m1.length,m2.length),b1=bytes(m1).slice(0,n),b2=bytes(m2).slice(0,n),kb=bytes(k);
  const c1=xor(b1,kb),c2=xor(b2,kb);X=c1.map((v,i)=>v^c2[i]);
  const mx=b1.map((v,i)=>v^b2[i]),same=toHex(X)===toHex(mx);
  const r=(l,v,c)=>`<div class="res"><small>${l}</small><code>${v}</code></div>`;
  o.innerHTML=(m1.length!==m2.length?`<div class="msg wa">Panjang pesan berbeda, hanya ${n} karakter pertama yang dipakai.</div>`:'')+
   r('C1 = M1 ⊕ K (dilihat penyerang)',toHex(c1))+r('C2 = M2 ⊕ K (dilihat penyerang)',toHex(c2))+
   `<div class="eq">C1 ⊕ C2</div>`+r('Dihitung dari ciphertext saja',toHex(X))+r('M1 ⊕ M2 (dihitung dari plaintext, pembanding)',toHex(mx))+
   `<div class="msg ${same?'ok':'er'}">${same?'✅ Sama persis. Kunci hilang dari persamaan, dan yang tersisa adalah hubungan langsung antara kedua pesan.':'❌ Hasil berbeda.'}</div>`;
};
$('bc').onclick=()=>{
  const c=$('cr').value,o=$('oc');
  if(!X){err(o,'Jalankan serangan di atas dulu agar C1 ⊕ C2 tersedia.');return}
  const e=chk(c,'Tebakan kata');if(e){err(o,e);return}
  if(c.length>X.length){err(o,`Tebakan (${c.length}) lebih panjang dari pesan (${X.length}).`);return}
  const cb=bytes(c);let h='<div class="sc"><table><thead><tr><th>Posisi</th><th>Jika tebakan ada di Pesan 1, maka Pesan 2 di posisi ini berisi</th></tr></thead><tbody>';
  for(let i=0;i+cb.length<=X.length;i++){
    const f=cb.map((v,j)=>v^X[i+j]),t=f.map(pr).join(''),hit=/^[A-Za-z0-9 .,!?'-]+$/.test(t);
    h+=`<tr class="${hit?'hit':''}"><td>${i}</td><td class="m">${esc(t)}</td></tr>`}
  o.innerHTML=h+'</tbody></table></div><p class="mu">Baris yang disorot berisi teks yang masuk akal, tanda tebakan mungkin benar. Dari sini kunci pun bisa dihitung: K = C1 ⊕ M1.</p>';
};

/* Syarat OTP */
function otpRender(){
  const s=last,B=(c,t)=>`<div class="st ${c}" style="background:none;padding:0">${t}</div>`;
  const wait=B('mu','Belum diperiksa. Jalankan enkripsi dulu.');
  const items=[
   ['Kunci benar-benar acak','Setiap bit tidak bisa ditebak. Gunakan pembangkit acak yang aman, bukan kata yang mudah diingat.',
     !s?wait:s.rand?B('ok','✓ Dibuat dengan crypto.getRandomValues (cukup untuk demo).'):B('wa','⚠ Diketik manual, kemungkinan tidak acak.')],
   ['Kunci ≥ panjang pesan','Setiap karakter pesan butuh byte kunci sendiri. Kunci pendek yang diulang membuat pola.',
     !s?wait:s.len?B('ok',`✓ Kunci ${s.kl} ≥ pesan ${s.n}.`):B('er',`✗ Kunci ${s.kl} &lt; pesan ${s.n}, keystream berulang.`)],
   ['Kunci dijaga rahasia','Hanya pengirim dan penerima yang tahu. Aplikasi tidak bisa memeriksa ini.',
     B('mu','Tanggung jawab pengguna: jangan tampilkan atau kirim lewat jalur yang sama dengan ciphertext.')],
   ['Kunci tidak pernah dipakai ulang','Satu kunci untuk satu pesan saja. Pemakaian ulang membuka serangan di tab sebelumnya.',
     !s?wait:s.reuse?B('er','✗ Kunci ini sudah dipakai untuk pesan lain.'):B('ok','✓ Belum pernah dipakai untuk pesan lain di sesi ini.')]];
  $('otpc').innerHTML=items.map(i=>`<div class="card"><h2 style="font-size:1rem">${i[0]}</h2><p class="mu" style="margin:0">${i[1]}</p>${i[2]}</div>`).join('');
}
otpRender();$('ba').click();
