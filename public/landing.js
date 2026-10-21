/* =========================================================
   SCRABL — LANDING SCRIPTS
   Used by: index.html
   Handles: mobile nav, testimonial carousel, feedback submit
   ========================================================= */

/* ---- mobile nav ---- */
function openNav(){ document.getElementById('mnav').classList.add('open'); document.body.style.overflow='hidden'; }
function closeNav(){ document.getElementById('mnav').classList.remove('open'); document.body.style.overflow=''; }

/* ---- testimonials ("Before We Launch") ---- */
var TESTIMONIALS = [
  ["“First thing… the idea is solid. The pain point is real and the positioning makes sense.”", "Mr. Jhano Paul", "Developer"],
  ["“I like the speed at which I received the waitlist code.”",                                   "Bayo",           "Content creator"],
  ["“Am naturally attracted to the idea & its potential.”",                                       "Ella",           "Graduate student"],
  ["“Am obsessed with the voice DNA, cant wait for full release.”",                               "Rae",            "Web3 enthusiast"],
  ["“The whole experience feels lighter. We await full launch.”",                                 "John",           "X writer"]
];

(function initTestimonials(){
  var tq = document.getElementById('tq');
  var tb = document.getElementById('tb');
  var dots = document.getElementById('tdots');
  if(!tq || !tb || !dots) return;

  var i = 0;

  TESTIMONIALS.forEach(function(_, idx){
    var b = document.createElement('button');
    if(idx === 0) b.className = 'on';
    b.addEventListener('click', function(){ show(idx); });
    dots.appendChild(b);
  });

  function show(n){
    i = (n + TESTIMONIALS.length) % TESTIMONIALS.length;
    tq.style.opacity = 0;
    setTimeout(function(){
      tq.textContent = TESTIMONIALS[i][0];
      tb.innerHTML = '<b>' + TESTIMONIALS[i][1] + '</b> · ' + TESTIMONIALS[i][2];
      tq.style.opacity = 1;
    }, 180);
    [].forEach.call(dots.children, function(d, j){ d.className = (j === i) ? 'on' : ''; });
  }

  var next = document.getElementById('tnext');
  var prev = document.getElementById('tprev');
  if(next) next.addEventListener('click', function(){ show(i + 1); });
  if(prev) prev.addEventListener('click', function(){ show(i - 1); });

  setInterval(function(){ show(i + 1); }, 5500);
})();

/* ---- feedback form → POST /api/feedback ---- */
(function initFeedback(){
  var form = document.getElementById('creator-feedback-form');
  if(!form) return;

  form.addEventListener('submit', function(e){
    e.preventDefault();
    var btn = form.querySelector('button[type=submit]');
    var msg = document.getElementById('fb-msg');

    var payload = {
      name:     document.getElementById('fb-name').value.trim(),
      email:    document.getElementById('fb-email').value.trim(),
      category: document.getElementById('fb-category').value,
      message:  document.getElementById('fb-message').value.trim(),
      rating:   document.getElementById('rating-input').value
    };

    btn.textContent = 'Sending…';
    btn.disabled = true;
    msg.textContent = '';

    fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(function(r){ return r.json().catch(function(){ return {}; }); })
      .then(function(){
        document.getElementById('fb-wrap').innerHTML =
          '<div class="fb-success"><h3>We heard you<span class="accent">.</span></h3>' +
          '<p>Your note is now part of the Scrabl roadmap. Keep creating.</p></div>';
      })
      .catch(function(){
        msg.textContent = 'Could not send right now — please try again.';
        btn.textContent = 'Send feedback';
        btn.disabled = false;
      });
  });
})();
