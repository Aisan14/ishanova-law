copy.ru.heroTitle='Правовая ясность <br/>в <em>непростых</em> ситуациях';
copy.kk.heroTitle='Күрделі жағдайда <br/><em>құқықтық айқындық</em>';
setLang(document.documentElement.lang);
const updateHeroDescription=lang=>{const label=lang==='kk'?'Заң кеңесінің заманауи кабинеті':'Современный кабинет юридической практики';document.querySelector('.hero-photo')?.setAttribute('alt',label);document.querySelector('.hero-visual')?.setAttribute('aria-label',label)};
updateHeroDescription(document.documentElement.lang);
document.querySelectorAll('.lang').forEach(button=>button.addEventListener('click',()=>updateHeroDescription(button.dataset.lang)));
