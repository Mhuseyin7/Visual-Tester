# Stack notları

Yalnızca tespit edilen stack'in bölümünü oku (`grep -n "^## " stack-notes.md`). Her bölüm: tespit, route listesini koddan çıkarma, tipik açıklar, hızlı grep.

## İçindekiler
1. Next.js (App/Pages Router)
2. Express / NestJS
3. Django / DRF
4. Flask / FastAPI
5. Laravel
6. ASP.NET Core
7. Spring Boot
8. Rails

---

## 1. Next.js

**Tespit:** `package.json` → `next`; `app/` veya `pages/` dizini; `next.config.*`.
**Route listesi:** `app/**/page.{tsx,jsx,js}`, `app/**/route.{ts,js}` (API), `pages/**/*.{tsx,jsx,js}`, `pages/api/**`. Dinamik segment `[id]` → `:id`. Server Actions: `grep -rn '"use server"'`.
**Tipik açıklar:**
- Yetki yalnızca `middleware.ts`'de, `matcher` bazı yolları kaçırıyor (ör. `/api` hariç tutulmuş). Middleware bypass: eski sürümlerde `x-middleware-subrequest` başlığı (CVE-2025-29927) → `next` sürümünü kontrol et.
- Server Action'lar herkese açık POST uçlarıdır; içlerinde oturum/yetki kontrolü yoksa BFLA.
- Route handler'larda `params.id` ile kayıt çekip sahiplik kontrolü yok (IDOR).
- `dangerouslySetInnerHTML`, `NEXT_PUBLIC_` önekli sırlar istemciye gömülür.
- `next.config` `images.remotePatterns` çok geniş → `/_next/image` SSRF benzeri proxy.
- `getServerSideProps` hata ayrıntısı, production'da source map (`productionBrowserSourceMaps: true`).
**Grep:** `grep -rnE "dangerouslySetInnerHTML|NEXT_PUBLIC_.*(SECRET|KEY|TOKEN)|use server|matcher|remotePatterns" --include=*.{ts,tsx,js,jsx} app pages src middleware.ts next.config.*`

## 2. Express / NestJS

**Tespit:** `express`, `@nestjs/core`, `fastify`, `koa`.
**Route listesi:** Express: `grep -rnE "(app|router)\.(get|post|put|patch|delete|all)\(" `. Nest: `@Controller('x')` + `@Get(':id')` vb.; guard'lar `@UseGuards`.
**Tipik açıklar:**
- Auth middleware route tanımından SONRA eklenmiş ya da bazı router'lara uygulanmamış.
- Nest'te global guard yok, `@UseGuards` bazı controller'larda unutulmuş; `ValidationPipe` `whitelist: true, forbidNonWhitelisted: true` olmadan → mass assignment.
- `req.body` doğrudan `Model.create/update`'e (Mongoose/Sequelize/Prisma) → mass assignment; Mongoose'ta `req.query` nesnesi → NoSQLi.
- `helmet` yok; `cors({origin: true, credentials: true})`.
- `express.static` ile upload dizini servis; `res.sendFile(req.query.path)`.
- Hata handler'ı `err.stack` döndürüyor; `NODE_ENV` production değil.
- `child_process.exec` + şablon string; `eval`, `vm`, `new Function`.
**Grep:** `grep -rnE "\.exec\(|execSync|eval\(|new Function|sendFile\(|\$where|findOne\(req\.(body|query)|create\(req\.body|update\w*\(.*req\.body|cors\(|helmet" --include=*.{js,ts} src lib routes`

## 3. Django / DRF

**Tespit:** `django` requirements/pyproject; `manage.py`; `settings.py`.
**Route listesi:** `urls.py` içinde `path(`/`re_path(`; DRF `router.register(`; `@api_view`.
**Tipik açıklar:**
- `DEBUG = True` / env'den default True; `ALLOWED_HOSTS = ['*']`.
- `SECRET_KEY` kodda sabit.
- DRF `DEFAULT_PERMISSION_CLASSES` `AllowAny`; viewset'te `get_queryset` kullanıcıya göre filtrelenmiyor (IDOR).
- Serializer `fields = '__all__'` → mass assignment ve aşırı veri dönüşü.
- `.raw(`, `.extra(`, `cursor.execute(f"...")` → SQLi; `mark_safe`, `|safe` → XSS.
- `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_SECURE`, `SECURE_HSTS_SECONDS` yok; `csrf_exempt`.
- Admin `/admin/` varsayılan yolda, MFA yok.
**Grep:** `grep -rnE "DEBUG\s*=|ALLOWED_HOSTS|SECRET_KEY\s*=|AllowAny|__all__|\.raw\(|\.extra\(|execute\(f|mark_safe|\|safe|csrf_exempt" --include=*.py`

## 4. Flask / FastAPI

**Tespit:** `flask`, `fastapi`, `starlette`.
**Route listesi:** `@app.route(`, `@bp.route(`, `@app.get(`/`@router.post(` vb.
**Tipik açıklar:**
- Flask `debug=True` veya `FLASK_DEBUG=1` → Werkzeug konsolu (RCE). `app.secret_key` sabit.
- `render_template_string(` + kullanıcı girdisi → SSTI.
- FastAPI'de `Depends(get_current_user)` bazı router'larda yok; Pydantic modeli ile ORM modelini aynı kullanma → mass assignment; `response_model` yok → aşırı veri dönüşü.
- `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`.
- `send_file(request.args['p'])`, `os.path.join(UPLOAD, filename)` `secure_filename` olmadan.
- `subprocess(..., shell=True)`, `os.system`, `pickle.loads`, `yaml.load` (Loader'sız).
- `/docs` ve `/openapi.json` production'da açık.
**Grep:** `grep -rnE "debug=True|secret_key\s*=|render_template_string|allow_origins|send_file\(|shell=True|os\.system|pickle\.loads|yaml\.load\(|text\(f|execute\(f" --include=*.py`

## 5. Laravel

**Tespit:** `composer.json` → `laravel/framework`; `artisan`.
**Route listesi:** `php artisan route:list --json` (yalnızca okuma, onaysız çalıştırılabilir) veya `routes/web.php`, `routes/api.php`.
**Tipik açıklar:**
- `.env` `APP_DEBUG=true` → Ignition hata sayfası (eski sürümlerde RCE CVE-2021-3129).
- Model `$guarded = []` veya `$fillable` içinde `is_admin`/`role` → mass assignment.
- Route'larda `auth` middleware var, `can:`/Policy yok → IDOR (`Order::find($id)`).
- `DB::raw(`, `whereRaw(` + string birleştirme; Blade `{!! $x !!}` → XSS.
- `storage/` veya `public/uploads` içine `.php` yüklenebilmesi.
- Telescope/Horizon/Debugbar production'da açık.
**Grep:** `grep -rnE "guarded\s*=\s*\[\]|fillable|DB::raw|whereRaw|selectRaw|\{!!|APP_DEBUG|Telescope|debugbar" app routes resources config .env.example`

## 6. ASP.NET Core

**Tespit:** `*.csproj` → `Microsoft.AspNetCore`; `Program.cs`.
**Route listesi:** `[Route(`, `[HttpGet(`, `app.Map(Get|Post|...)(`; Razor Pages `Pages/**/*.cshtml`.
**Tipik açıklar:**
- `[Authorize]` controller'da var, bazı action'larda `[AllowAnonymous]`; global `FallbackPolicy` yok.
- Policy/resource-based authorization yok → IDOR.
- Model binding entity'ye doğrudan (`[FromBody] User user`) → overposting.
- `FromSqlRaw($"...")` → SQLi; `Html.Raw(` → XSS.
- `app.UseDeveloperExceptionPage()` ortam kontrolsüz; `ASPNETCORE_ENVIRONMENT=Development`.
- `AllowAnyOrigin().AllowCredentials()` (çalışma zamanında hata verir) ya da `SetIsOriginAllowed(_ => true)`.
- `BinaryFormatter`, `TypeNameHandling.All` (Newtonsoft) → deserialization.
**Grep:** `grep -rnE "AllowAnonymous|FromSqlRaw|ExecuteSqlRaw|Html\.Raw|UseDeveloperExceptionPage|SetIsOriginAllowed|TypeNameHandling|BinaryFormatter" --include=*.cs`

## 7. Spring Boot

**Tespit:** `pom.xml`/`build.gradle` → `spring-boot-starter-web`.
**Route listesi:** `@RequestMapping`, `@GetMapping` vb.; `SecurityFilterChain` içindeki `requestMatchers`.
**Tipik açıklar:**
- `SecurityFilterChain` içinde `permitAll()` çok geniş (`/api/**`), sıralama hatası.
- Actuator uçları açık (`management.endpoints.web.exposure.include=*`) → `/actuator/env`, `/heapdump`.
- `@PreAuthorize` sahiplik kontrolü yok → IDOR.
- Entity'yi doğrudan `@RequestBody` → mass assignment.
- JPQL/SQL string birleştirme (`createQuery("..." + x)`), `@Query(nativeQuery=true)` + concat.
- CSRF `disable()` + cookie oturum.
- SpEL/Thymeleaf `__${...}__` ön işleme → SSTI.
**Grep:** `grep -rnE "permitAll|csrf\(\)\.disable|csrf\(.*disable|exposure\.include|createQuery\(.*\+|nativeQuery|__\\\$\{" --include=*.{java,kt,properties,yml,yaml}`

## 8. Rails

**Tespit:** `Gemfile` → `rails`; `config/routes.rb`.
**Route listesi:** `bin/rails routes` (okuma) veya `config/routes.rb`.
**Tipik açıklar:**
- `before_action :authenticate_user!` bazı controller'larda yok veya `skip_before_action`.
- `Model.find(params[:id])` yerine `current_user.models.find` kullanılmamış → IDOR.
- `params.permit!` veya geniş `permit(:role, :admin)` → mass assignment.
- `where("name = '#{params[:q]}'")`, `order(params[:sort])` → SQLi.
- `html_safe`, `raw(` → XSS; `render inline:` → SSTI.
- `protect_from_forgery` kapalı (API olmayan controller).
- `config.consider_all_requests_local = true` production'da; `secret_key_base` repoda.
**Grep:** `grep -rnE "skip_before_action|permit!|where\(\".*#\{|order\(params|html_safe|raw\(|render inline|protect_from_forgery|consider_all_requests_local" app config`

---

## Ortak: route listesi formatı

`.visual-tester/code-routes.json`:
```json
[{"method":"GET","path":"/admin/users/:id","file":"src/routes/admin.ts:42","auth":"session","note":"UI'da link yok"}]
```
`inventory.mjs --compare-routes` bu dosyayı okur; `path` normalize edilir (`[id]`, `{id}`, `<int:id>` → `:id`).
