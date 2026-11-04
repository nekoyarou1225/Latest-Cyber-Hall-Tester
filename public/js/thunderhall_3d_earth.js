/**
 * THUNDERHALL TESTER — 3D Earth, International Communication Routes & Satellite Orbits Engine
 * Design System: GLOBAL CYBER DEFENSE COMMAND CENTER
 *
 * Uses Three.js (WebGLRenderer) with 100% local Natural Earth geographic data.
 * Features:
 *  - 7 Continents + Major Islands (Japan 4 main islands + Okinawa, Greenland, UK, NZ, etc.)
 *  - High-contrast Deep Navy Ocean (#030914 ~ #071426) & Cyber Teal Continents (#0E4864 ~ #1D6E8E)
 *  - Metropolitan Night City Lights (#F5B942 Gold & #35D9FF Cyan clusters)
 *  - Solar Terminator (Day/Night subtle shading) & Dual-Layer Fresnel Atmosphere Glow
 *  - Strict Back-of-Earth Spherical Occlusion (dot(N, V) > 0.08) for hubs & city labels
 *  - 3D Great-Circle Communication Arcs, Moving Light Packets & 6-Step Arrival Ripples
 *  - 3D Satellite Orbits (LEO / MEO / GEO) + Ground Station Beams
 *  - CameraDirector State Snapshot Save / Restore (saveViewState / restoreViewState)
 */
import * as THREE from '/vendor/three/three.module.js';

window.THREE = THREE;

const EARTH_RADIUS = 10.0;
const DEG2RAD = Math.PI / 180;

// 12 Required Major Global Cities (Section 4.3)
export const MAJOR_12_CITIES = [
  { id: 'CITY_TYO', name_en: 'Tokyo', name_ja: '東京', lat: 35.6895, lon: 139.6917, isCapitalHub: true },
  { id: 'CITY_OSA', name_en: 'Osaka', name_ja: '大阪', lat: 34.6937, lon: 135.5023, isCapitalHub: false },
  { id: 'CITY_SEL', name_en: 'Seoul', name_ja: 'ソウル', lat: 37.5665, lon: 126.9780, isCapitalHub: false },
  { id: 'CITY_BJS', name_en: 'Beijing', name_ja: '北京', lat: 39.9042, lon: 116.4074, isCapitalHub: true },
  { id: 'CITY_SIN', name_en: 'Singapore', name_ja: 'シンガポール', lat: 1.3521, lon: 103.8198, isCapitalHub: true },
  { id: 'CITY_SYD', name_en: 'Sydney', name_ja: 'シドニー', lat: -33.8688, lon: 151.2093, isCapitalHub: false },
  { id: 'CITY_LON', name_en: 'London', name_ja: 'ロンドン', lat: 51.5074, lon: -0.1278, isCapitalHub: true },
  { id: 'CITY_PAR', name_en: 'Paris', name_ja: 'パリ', lat: 48.8566, lon: 2.3522, isCapitalHub: true },
  { id: 'CITY_FRA', name_en: 'Frankfurt', name_ja: 'フランクフルト', lat: 50.1109, lon: 8.6821, isCapitalHub: false },
  { id: 'CITY_NYC', name_en: 'New York', name_ja: 'ニューヨーク', lat: 40.7128, lon: -74.0060, isCapitalHub: true },
  { id: 'CITY_SFO', name_en: 'San Francisco', name_ja: 'サンフランシスコ', lat: 37.7749, lon: -122.4194, isCapitalHub: false },
  { id: 'CITY_GRU', name_en: 'Sao Paulo', name_ja: 'サンパウロ', lat: -23.5505, lon: -46.6333, isCapitalHub: false }
];

export function latLonToVector3(lat, lon, radius = EARTH_RADIUS) {
  const theta = (90 - lat) * DEG2RAD;
  const phi = (lon + 180) * DEG2RAD;
  const x = -radius * Math.sin(theta) * Math.cos(phi);
  const y = radius * Math.cos(theta);
  const z = radius * Math.sin(theta) * Math.sin(phi);
  return new THREE.Vector3(x, y, z);
}

/**
 * Generates high-resolution 2:1 Equirectangular Earth textures (Albedo + Night City Lights, Bump, Roughness)
 */
function buildEquirectangularEarthTextures(geoData, isSoftwareGl) {
  const width = isSoftwareGl ? 2048 : 4096;
  const height = width / 2;

  const albedoCanvas = document.createElement('canvas');
  albedoCanvas.width = width;
  albedoCanvas.height = height;
  const ctx = albedoCanvas.getContext('2d');

  const bumpCanvas = document.createElement('canvas');
  bumpCanvas.width = width;
  bumpCanvas.height = height;
  const bCtx = bumpCanvas.getContext('2d');

  const roughCanvas = document.createElement('canvas');
  roughCanvas.width = width;
  roughCanvas.height = height;
  const rCtx = roughCanvas.getContext('2d');

  // --- 1. Deep Cosmic Navy Ocean Base (#030914 ~ #071426 ~ #091E36) ---
  const oceanGrad = ctx.createLinearGradient(0, 0, 0, height);
  oceanGrad.addColorStop(0.0, '#030914');
  oceanGrad.addColorStop(0.18, '#061325');
  oceanGrad.addColorStop(0.5, '#081C34');
  oceanGrad.addColorStop(0.82, '#061325');
  oceanGrad.addColorStop(1.0, '#030914');
  ctx.fillStyle = oceanGrad;
  ctx.fillRect(0, 0, width, height);

  // Subtle Precision Graticule on Ocean Surface
  ctx.strokeStyle = 'rgba(53, 217, 255, 0.05)';
  ctx.lineWidth = Math.max(1, width / 2048);
  for (let lon = -180; lon <= 180; lon += 15) {
    const x = ((lon + 180) / 360) * width;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
  for (let lat = -75; lat <= 75; lat += 15) {
    const y = ((90 - lat) / 180) * height;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  bCtx.fillStyle = '#000000';
  bCtx.fillRect(0, 0, width, height);

  // Ocean roughness: smooth specular reflection for horizon light
  rCtx.fillStyle = '#525252';
  rCtx.fillRect(0, 0, width, height);

  const lonToX = (lon) => ((lon + 180) / 360) * width;
  const latToY = (lat) => ((90 - lat) / 180) * height;

  const traceRing = (targetCtx, ring) => {
    if (!ring || ring.length < 3) return;
    targetCtx.beginPath();
    for (let i = 0; i < ring.length; i++) {
      const [lon, lat] = ring[i];
      const x = lonToX(lon);
      const y = latToY(lat);
      if (i === 0) targetCtx.moveTo(x, y);
      else targetCtx.lineTo(x, y);
    }
    targetCtx.closePath();
  };

  // --- 2. Continental Shelf Outer Glow ---
  ctx.save();
  ctx.shadowColor = 'rgba(53, 217, 255, 0.28)';
  ctx.shadowBlur = width * 0.007;
  ctx.fillStyle = '#0A243C';
  for (const poly of geoData.landmassPolygons) {
    for (const ring of poly.rings) {
      traceRing(ctx, ring);
      ctx.fill();
    }
  }
  ctx.restore();

  // --- 3. High-Visibility Continents Fill (Cyber Teal / Blue-Green) ---
  for (const poly of geoData.landmassPolygons) {
    const isJapan = poly.category === 'japan';
    for (const ring of poly.rings) {
      const landGrad = ctx.createLinearGradient(0, 0, 0, height);
      if (isJapan) {
        landGrad.addColorStop(0.0, '#1D6B82');
        landGrad.addColorStop(0.5, '#25839E');
        landGrad.addColorStop(1.0, '#195E73');
      } else {
        landGrad.addColorStop(0.0, '#12485E');
        landGrad.addColorStop(0.35, '#15546D');
        landGrad.addColorStop(0.5, '#18607B');
        landGrad.addColorStop(0.7, '#134D64');
        landGrad.addColorStop(1.0, '#104155');
      }
      ctx.fillStyle = landGrad;
      traceRing(ctx, ring);
      ctx.fill();

      bCtx.fillStyle = isJapan ? '#C8C8C8' : '#828282';
      traceRing(bCtx, ring);
      bCtx.fill();

      rCtx.fillStyle = '#D0D0D0';
      traceRing(rCtx, ring);
      rCtx.fill();
    }
  }

  // --- 4. Metropolitan Night City Light Clusters (Gold #F5B942 & Cyan #35D9FF) ---
  ctx.save();
  ctx.globalCompositeOperation = 'source-atop';
  for (const city of MAJOR_12_CITIES) {
    const cx = lonToX(city.lon);
    const cy = latToY(city.lat);
    const outerR = width * (city.isCapitalHub ? 0.018 : 0.012);
    const cityGrad = ctx.createRadialGradient(cx, cy, 0, cx, cy, outerR);
    cityGrad.addColorStop(0.0, 'rgba(255, 227, 160, 0.72)');
    cityGrad.addColorStop(0.28, 'rgba(245, 185, 66, 0.36)');
    cityGrad.addColorStop(0.65, 'rgba(53, 217, 255, 0.14)');
    cityGrad.addColorStop(1.0, 'rgba(9, 28, 48, 0)');
    ctx.fillStyle = cityGrad;
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();

  // --- 5. Country Borders inside Continents ---
  ctx.strokeStyle = 'rgba(53, 217, 255, 0.28)';
  ctx.lineWidth = Math.max(1.0, width / 2048);
  for (const borderLine of geoData.countryBorders || []) {
    if (borderLine.length < 2) continue;
    ctx.beginPath();
    for (let i = 0; i < borderLine.length; i++) {
      const [lon, lat] = borderLine[i];
      const x = lonToX(lon);
      const y = latToY(lat);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }

  // --- 6. Luminous Continental Coastlines ---
  for (const poly of geoData.landmassPolygons) {
    const isJapan = poly.category === 'japan';
    ctx.strokeStyle = isJapan ? 'rgba(139, 234, 255, 0.92)' : 'rgba(53, 217, 255, 0.62)';
    ctx.lineWidth = isJapan ? Math.max(2.2, width / 1100) : Math.max(1.4, width / 1700);
    for (const ring of poly.rings) {
      traceRing(ctx, ring);
      ctx.stroke();
    }
  }

  const albedoTex = new THREE.CanvasTexture(albedoCanvas);
  albedoTex.colorSpace = THREE.SRGBColorSpace;
  albedoTex.anisotropy = 4;
  albedoTex.needsUpdate = true;

  const bumpTex = new THREE.CanvasTexture(bumpCanvas);
  bumpTex.needsUpdate = true;

  const roughTex = new THREE.CanvasTexture(roughCanvas);
  roughTex.needsUpdate = true;

  return { albedoTex, bumpTex, roughTex };
}

/**
 * Builds 3D Vector Coastline and Country Border LineSegments on the sphere surface
 */
function build3DCoastlineAndBorderMeshes(geoData) {
  const group = new THREE.Group();
  const coastPositions = [];
  const japanPositions = [];
  const borderPositions = [];

  const rCoast = EARTH_RADIUS * 1.0018;
  const rJapan = EARTH_RADIUS * 1.0028;
  const rBorder = EARTH_RADIUS * 1.0012;

  for (const poly of geoData.landmassPolygons) {
    const isJp = poly.category === 'japan';
    const targetArr = isJp ? japanPositions : coastPositions;
    const rad = isJp ? rJapan : rCoast;

    for (const ring of poly.rings) {
      for (let i = 0; i < ring.length - 1; i++) {
        const [lon1, lat1] = ring[i];
        const [lon2, lat2] = ring[i + 1];
        const steps = Math.max(1, Math.ceil(Math.hypot(lon2 - lon1, lat2 - lat1) / 2.5));
        for (let s = 0; s < steps; s++) {
          const t0 = s / steps;
          const t1 = (s + 1) / steps;
          const p0 = latLonToVector3(lat1 + (lat2 - lat1) * t0, lon1 + (lon2 - lon1) * t0, rad);
          const p1 = latLonToVector3(lat1 + (lat2 - lat1) * t1, lon1 + (lon2 - lon1) * t1, rad);
          targetArr.push(p0.x, p0.y, p0.z, p1.x, p1.y, p1.z);
        }
      }
    }
  }

  for (const bline of geoData.countryBorders || []) {
    for (let i = 0; i < bline.length - 1; i++) {
      const [lon1, lat1] = bline[i];
      const [lon2, lat2] = bline[i + 1];
      const steps = Math.max(1, Math.ceil(Math.hypot(lon2 - lon1, lat2 - lat1) / 3.0));
      for (let s = 0; s < steps; s++) {
        const t0 = s / steps;
        const t1 = (s + 1) / steps;
        const p0 = latLonToVector3(lat1 + (lat2 - lat1) * t0, lon1 + (lon2 - lon1) * t0, rBorder);
        const p1 = latLonToVector3(lat1 + (lat2 - lat1) * t1, lon1 + (lon2 - lon1) * t1, rBorder);
        borderPositions.push(p0.x, p0.y, p0.z, p1.x, p1.y, p1.z);
      }
    }
  }

  if (coastPositions.length > 0) {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(coastPositions, 3));
    const mat = new THREE.LineBasicMaterial({
      color: 0x35d9ff,
      transparent: true,
      opacity: 0.52,
      depthWrite: false
    });
    group.add(new THREE.LineSegments(geo, mat));
  }

  if (japanPositions.length > 0) {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(japanPositions, 3));
    const mat = new THREE.LineBasicMaterial({
      color: 0x8beaff,
      transparent: true,
      opacity: 0.95,
      depthWrite: false
    });
    group.add(new THREE.LineSegments(geo, mat));
  }

  if (borderPositions.length > 0) {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.Float32BufferAttribute(borderPositions, 3));
    const mat = new THREE.LineBasicMaterial({
      color: 0x35d9ff,
      transparent: true,
      opacity: 0.22,
      depthWrite: false
    });
    group.add(new THREE.LineSegments(geo, mat));
  }

  return group;
}

/**
 * Creates the Cyber Blue / Cyan Fresnel atmospheric rim glow around the 3D Earth (Section 4.1)
 */
function buildAtmosphereMesh() {
  const atmosGeo = new THREE.SphereGeometry(EARTH_RADIUS * 1.052, 64, 48);
  const atmosMat = new THREE.ShaderMaterial({
    uniforms: {
      glowColor: { value: new THREE.Color(0x168bff) },
      cyanColor: { value: new THREE.Color(0x35d9ff) }
    },
    vertexShader: `
      varying vec3 vNormal;
      varying vec3 vWorldPos;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        vec4 worldPosition = modelMatrix * vec4(position, 1.0);
        vWorldPos = worldPosition.xyz;
        gl_Position = projectionMatrix * viewMatrix * worldPosition;
      }
    `,
    fragmentShader: `
      uniform vec3 glowColor;
      uniform vec3 cyanColor;
      varying vec3 vNormal;
      varying vec3 vWorldPos;
      void main() {
        vec3 viewDir = normalize(cameraPosition - vWorldPos);
        float rim = 1.0 - max(0.0, dot(viewDir, vNormal));
        float intensity = pow(rim, 3.1) * 0.72;
        vec3 col = mix(glowColor, cyanColor, 0.45);
        gl_FragColor = vec4(col, intensity);
      }
    `,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    side: THREE.FrontSide
  });

  const outerGeo = new THREE.SphereGeometry(EARTH_RADIUS * 1.115, 64, 48);
  const outerMat = new THREE.ShaderMaterial({
    uniforms: {
      glowColor: { value: new THREE.Color(0x00afff) }
    },
    vertexShader: `
      varying vec3 vNormal;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: `
      uniform vec3 glowColor;
      varying vec3 vNormal;
      void main() {
        float intensity = pow(0.62 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.5);
        gl_FragColor = vec4(glowColor, clamp(intensity * 0.46, 0.0, 0.44));
      }
    `,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    side: THREE.BackSide
  });

  const group = new THREE.Group();
  group.add(new THREE.Mesh(atmosGeo, atmosMat));
  group.add(new THREE.Mesh(outerGeo, outerMat));
  return group;
}

/**
 * Builds a Great-Circle 3D curved arc between two (lat, lon) points on the Earth's surface.
 */
function createGreatCircleCurve(lat1, lon1, lat2, lon2, maxLiftFactor = 0.22) {
  const vStart = latLonToVector3(lat1, lon1, 1.0).normalize();
  const vEnd = latLonToVector3(lat2, lon2, 1.0).normalize();
  const omega = Math.acos(THREE.MathUtils.clamp(vStart.dot(vEnd), -1.0, 1.0));
  const sinOmega = Math.sin(omega);

  const numPoints = 36;
  const points = [];
  const dynamicLift = Math.min(0.32, Math.max(0.07, (omega / Math.PI) * maxLiftFactor * 1.45));

  for (let i = 0; i <= numPoints; i++) {
    const t = i / numPoints;
    let dir;
    if (sinOmega < 0.0001) {
      dir = vStart.clone().lerp(vEnd, t).normalize();
    } else {
      const w0 = Math.sin((1 - t) * omega) / sinOmega;
      const w1 = Math.sin(t * omega) / sinOmega;
      dir = vStart.clone().multiplyScalar(w0).add(vEnd.clone().multiplyScalar(w1)).normalize();
    }
    const altitude = EARTH_RADIUS * (1.003 + Math.sin(Math.PI * t) * dynamicLift);
    points.push(dir.multiplyScalar(altitude));
  }

  return new THREE.CatmullRomCurve3(points);
}

/**
 * Creates a sprite label for the 12 major global cities (Section 4.3)
 */
function createCityLabelSprite(city) {
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 64;
  const ctx = canvas.getContext('2d');

  ctx.fillStyle = 'rgba(3, 9, 20, 0.78)';
  ctx.strokeStyle = city.isCapitalHub ? 'rgba(245, 185, 66, 0.75)' : 'rgba(53, 217, 255, 0.55)';
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.roundRect(6, 10, 244, 44, 8);
  ctx.fill();
  ctx.stroke();

  ctx.fillStyle = city.isCapitalHub ? '#FFE3A0' : '#8BEAFF';
  ctx.font = '700 20px "JetBrains Mono", monospace';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${city.name_en.toUpperCase()} · ${city.name_ja}`, 128, 32);

  const tex = new THREE.CanvasTexture(canvas);
  tex.colorSpace = THREE.SRGBColorSpace;
  const mat = new THREE.SpriteMaterial({
    map: tex,
    transparent: true,
    depthTest: true,
    depthWrite: false
  });
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(1.65, 0.42, 1);
  return sprite;
}

/**
 * Builds a 3D composite satellite model (Metallic Bus + Gold Thermal Foil + Solar Wings + Comms Dish)
 */
function createSatellite3DModel(accentColorHex) {
  const satGroup = new THREE.Group();

  const busGeo = new THREE.BoxGeometry(0.26, 0.22, 0.34);
  const busMat = new THREE.MeshStandardMaterial({
    color: 0xf5b942,
    metalness: 0.78,
    roughness: 0.24
  });
  satGroup.add(new THREE.Mesh(busGeo, busMat));

  const wingGeo = new THREE.BoxGeometry(1.18, 0.025, 0.26);
  const wingMat = new THREE.MeshStandardMaterial({
    color: 0x091c30,
    emissive: new THREE.Color(accentColorHex),
    emissiveIntensity: 0.32,
    metalness: 0.65,
    roughness: 0.2
  });
  satGroup.add(new THREE.Mesh(wingGeo, wingMat));

  const dishGeo = new THREE.ConeGeometry(0.14, 0.14, 16);
  const dishMat = new THREE.MeshStandardMaterial({
    color: 0xffffff,
    metalness: 0.5,
    roughness: 0.3
  });
  const dish = new THREE.Mesh(dishGeo, dishMat);
  dish.position.set(0, -0.18, 0);
  satGroup.add(dish);

  const beaconGeo = new THREE.SphereGeometry(0.08, 12, 12);
  const beaconMat = new THREE.MeshBasicMaterial({ color: accentColorHex });
  satGroup.add(new THREE.Mesh(beaconGeo, beaconMat));

  return satGroup;
}

/**
 * Main 3D Earth Command Center Controller
 */
export function initThunderhallEarth3D(canvasEl) {
  const geoData = window.THUNDERHALL_NATURAL_EARTH;
  if (!canvasEl || !geoData) return null;

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas: canvasEl,
      antialias: true,
      alpha: false,
      powerPreference: 'high-performance'
    });
  } catch (err) {
    console.warn('WebGLRenderer fallback check:', err);
    return null;
  }

  const gl = renderer.getContext();
  const debugExt = gl.getExtension('WEBGL_debug_renderer_info');
  const glRendererStr = debugExt ? String(gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL)) : '';
  const isSoftwareGl = /SwiftShader|llvmpipe|Software/i.test(glRendererStr);

  renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.setClearColor(0x030914, 1.0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1.6, 0.1, 400);

  // --- Lighting Setup (Cinematic Space Lighting + Day/Night Balance) ---
  const ambientLight = new THREE.AmbientLight(0x8beaff, 1.18);
  scene.add(ambientLight);

  const hemiLight = new THREE.HemisphereLight(0x35d9ff, 0x030914, 0.68);
  scene.add(hemiLight);

  const sunLight = new THREE.DirectionalLight(0xffffff, 1.92);
  sunLight.position.set(28, 16, 24);
  scene.add(sunLight);

  const rimLight = new THREE.DirectionalLight(0x168bff, 1.05);
  rimLight.position.set(-24, -12, -20);
  scene.add(rimLight);

  // --- Deep Space Starfield (Subtle & Cinematic) ---
  const starCount = isSoftwareGl ? 900 : 1800;
  const starPositions = new Float32Array(starCount * 3);
  const starColors = new Float32Array(starCount * 3);
  for (let i = 0; i < starCount; i++) {
    const r = 85 + Math.random() * 110;
    const u = Math.random();
    const v = Math.random();
    const theta = 2 * Math.PI * u;
    const phi = Math.acos(2 * v - 1);
    starPositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
    starPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
    starPositions[i * 3 + 2] = r * Math.cos(phi);

    const tint =
      i % 5 === 0
        ? new THREE.Color(0x35d9ff)
        : i % 9 === 0
          ? new THREE.Color(0xf5b942)
          : new THREE.Color(0xc5d8f0);
    starColors[i * 3] = tint.r;
    starColors[i * 3 + 1] = tint.g;
    starColors[i * 3 + 2] = tint.b;
  }
  const starGeo = new THREE.BufferGeometry();
  starGeo.setAttribute('position', new THREE.BufferAttribute(starPositions, 3));
  starGeo.setAttribute('color', new THREE.BufferAttribute(starColors, 3));
  const starMat = new THREE.PointsMaterial({
    size: 0.4,
    vertexColors: true,
    transparent: true,
    opacity: 0.65,
    depthWrite: false
  });
  const starField = new THREE.Points(starGeo, starMat);
  scene.add(starField);

  // --- Root World Pivot ---
  const earthPivot = new THREE.Group();
  scene.add(earthPivot);

  // --- 3D Earth Sphere ---
  const { albedoTex, bumpTex, roughTex } = buildEquirectangularEarthTextures(geoData, isSoftwareGl);
  const earthGeo = new THREE.SphereGeometry(EARTH_RADIUS, isSoftwareGl ? 64 : 96, isSoftwareGl ? 48 : 64);
  const earthMat = new THREE.MeshStandardMaterial({
    map: albedoTex,
    bumpMap: bumpTex,
    bumpScale: 0.16,
    roughnessMap: roughTex,
    roughness: 0.68,
    metalness: 0.16
  });
  const earthMesh = new THREE.Mesh(earthGeo, earthMat);
  earthPivot.add(earthMesh);

  // --- 3D Coastlines & Country Borders ---
  const coastlineGroup = build3DCoastlineAndBorderMeshes(geoData);
  earthPivot.add(coastlineGroup);

  // --- Atmosphere Halo ---
  const atmosphereGroup = buildAtmosphereMesh();
  earthPivot.add(atmosphereGroup);

  // --- Hub Nodes Map, 12 Major City Labels & Surface Beacons ---
  const hubById = new Map();
  const hubBeaconsGroup = new THREE.Group();
  earthPivot.add(hubBeaconsGroup);

  const hubMeshes = [];
  const hubRingGeo = new THREE.RingGeometry(0.11, 0.19, 24);
  const hubCoreGeo = new THREE.SphereGeometry(0.085, 16, 16);

  for (const hub of geoData.globalCyberHubs) {
    hubById.set(hub.id, hub);
    const pos = latLonToVector3(hub.lat, hub.lon, EARTH_RADIUS * 1.003);
    const normal = pos.clone().normalize();
    const isJapan = hub.country_en === 'Japan';

    const coreMat = new THREE.MeshBasicMaterial({
      color: isJapan ? 0x27e59a : 0x35d9ff
    });
    const coreMesh = new THREE.Mesh(hubCoreGeo, coreMat);
    coreMesh.position.copy(pos);
    hubBeaconsGroup.add(coreMesh);

    const ringMat = new THREE.MeshBasicMaterial({
      color: isJapan ? 0xf5b942 : 0x35d9ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0.78,
      depthWrite: false
    });
    const ringMesh = new THREE.Mesh(hubRingGeo, ringMat);
    ringMesh.position.copy(pos);
    ringMesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal);
    hubBeaconsGroup.add(ringMesh);

    hubMeshes.push({ hub, coreMesh, ringMesh, normal });
  }

  // 12 Major Cities with 3D Sprites and Strict Occlusion
  const cityMarkers = [];
  for (const city of MAJOR_12_CITIES) {
    const surfacePos = latLonToVector3(city.lat, city.lon, EARTH_RADIUS * 1.004);
    const labelPos = latLonToVector3(city.lat, city.lon, EARTH_RADIUS * 1.042);
    const normal = surfacePos.clone().normalize();

    const dotGeo = new THREE.SphereGeometry(city.isCapitalHub ? 0.095 : 0.07, 12, 12);
    const dotMat = new THREE.MeshBasicMaterial({
      color: city.isCapitalHub ? 0xf5b942 : 0x35d9ff
    });
    const dotMesh = new THREE.Mesh(dotGeo, dotMat);
    dotMesh.position.copy(surfacePos);
    hubBeaconsGroup.add(dotMesh);

    const labelSprite = createCityLabelSprite(city);
    labelSprite.position.copy(labelPos);
    hubBeaconsGroup.add(labelSprite);

    cityMarkers.push({ city, dotMesh, labelSprite, normal });
  }

  // --- International Communication Arcs, Moving Particles & 6-Step Arrival Ripples ---
  const routesGroup = new THREE.Group();
  earthPivot.add(routesGroup);

  const activeSegmentParticles = [];
  const arrivalRipplePool = [];
  const rippleGeo = new THREE.RingGeometry(0.14, 0.22, 32);
  const outerRippleGeo = new THREE.RingGeometry(0.24, 0.31, 32);

  for (let i = 0; i < 16; i++) {
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x35d9ff,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0,
      depthWrite: false
    });
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x27e59a,
      side: THREE.DoubleSide,
      transparent: true,
      opacity: 0,
      depthWrite: false
    });
    const innerRing = new THREE.Mesh(rippleGeo, innerMat);
    const outerRing = new THREE.Mesh(outerRippleGeo, outerMat);
    innerRing.visible = false;
    outerRing.visible = false;
    routesGroup.add(innerRing);
    routesGroup.add(outerRing);
    arrivalRipplePool.push({
      active: false,
      progress: 0,
      innerRing,
      outerRing,
      innerMat,
      outerMat,
      normal: new THREE.Vector3(0, 0, 1)
    });
  }

  function triggerArrivalRippleAtHub(hub, colorHex, routeObj) {
    const slot = arrivalRipplePool.find((r) => !r.active) || arrivalRipplePool[0];
    const pos = latLonToVector3(hub.lat, hub.lon, EARTH_RADIUS * 1.0045);
    const normal = pos.clone().normalize();
    const quat = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 0, 1), normal);

    slot.active = true;
    slot.progress = 0;
    slot.normal.copy(normal);
    slot.innerMat.color.set(colorHex);
    slot.outerMat.color.set(routeObj.accent_color || '#27E59A');
    slot.innerRing.position.copy(pos);
    slot.outerRing.position.copy(pos);
    slot.innerRing.quaternion.copy(quat);
    slot.outerRing.quaternion.copy(quat);
    slot.innerRing.scale.setScalar(1.0);
    slot.outerRing.scale.setScalar(1.0);
    slot.innerRing.visible = true;
    slot.outerRing.visible = true;

    updateCommandTargetPanel(hub, routeObj);
  }

  const particleGeo = new THREE.SphereGeometry(0.115, 12, 12);
  const trailGeo = new THREE.SphereGeometry(0.075, 10, 10);

  for (let rIdx = 0; rIdx < geoData.internationalRoutes.length; rIdx++) {
    const route = geoData.internationalRoutes[rIdx];
    const hops = route.hops;
    for (let h = 0; h < hops.length - 1; h++) {
      const originHub = hubById.get(hops[h]);
      const targetHub = hubById.get(hops[h + 1]);
      if (!originHub || !targetHub) continue;

      const curve = createGreatCircleCurve(originHub.lat, originHub.lon, targetHub.lat, targetHub.lon, 0.21);
      const midNormal = curve.getPointAt(0.5).clone().normalize();

      const tubeGeo = new THREE.TubeGeometry(curve, 44, 0.036, 8, false);
      const tubeMat = new THREE.MeshBasicMaterial({
        color: new THREE.Color(route.severity_color),
        transparent: true,
        opacity: 0.62,
        depthWrite: false
      });
      const tubeMesh = new THREE.Mesh(tubeGeo, tubeMat);
      routesGroup.add(tubeMesh);

      const linePts = curve.getPoints(48);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(linePts);
      const lineMat = new THREE.LineBasicMaterial({
        color: new THREE.Color(route.accent_color || '#35D9FF'),
        transparent: true,
        opacity: 0.88
      });
      const lineMesh = new THREE.Line(lineGeo, lineMat);
      routesGroup.add(lineMesh);

      const headMat = new THREE.MeshBasicMaterial({ color: 0xffffff });
      const headMesh = new THREE.Mesh(particleGeo, headMat);
      const trailMat = new THREE.MeshBasicMaterial({
        color: new THREE.Color(route.severity_color),
        transparent: true,
        opacity: 0.82
      });
      const trailMesh1 = new THREE.Mesh(trailGeo, trailMat);
      const trailMesh2 = new THREE.Mesh(trailGeo, trailMat);

      routesGroup.add(headMesh);
      routesGroup.add(trailMesh1);
      routesGroup.add(trailMesh2);

      activeSegmentParticles.push({
        route,
        originHub,
        targetHub,
        curve,
        midNormal,
        tubeMesh,
        lineMesh,
        headMesh,
        trailMesh1,
        trailMesh2,
        t: (rIdx * 0.19 + h * 0.31) % 1.0,
        speed: 0.24 + (rIdx % 3) * 0.045
      });
    }
  }

  // --- 3D Satellite Orbits (LEO / MEO / GEO) ---
  const satellitesGroup = new THREE.Group();
  earthPivot.add(satellitesGroup);

  const orbitConfigs = [
    {
      id: 'LEO-STAR-01',
      name_ja: '低軌道通信衛星 LEO-01 (SIMULATED)',
      radius: EARTH_RADIUS * 1.24,
      inclinationX: 0.52,
      inclinationZ: -0.28,
      speed: 0.38,
      phase: 0.2,
      color: 0x35d9ff,
      groundHubId: 'HUB_JPN_TYO'
    },
    {
      id: 'LEO-SENTINEL-02',
      name_ja: '極軌道監視衛星 LEO-02 (SIMULATED)',
      radius: EARTH_RADIUS * 1.29,
      inclinationX: 1.12,
      inclinationZ: 0.42,
      speed: 0.32,
      phase: 2.1,
      color: 0x27e59a,
      groundHubId: 'HUB_FRA_PAR'
    },
    {
      id: 'MEO-RELAY-03',
      name_ja: '中軌道中継衛星 MEO-03 (SIMULATED)',
      radius: EARTH_RADIUS * 1.44,
      inclinationX: -0.45,
      inclinationZ: 0.65,
      speed: 0.21,
      phase: 3.8,
      color: 0xf5b942,
      groundHubId: 'HUB_USA_DC'
    },
    {
      id: 'GEO-AETHER-04',
      name_ja: '静止軌道防衛衛星 GEO-04 (SIMULATED)',
      radius: EARTH_RADIUS * 1.62,
      inclinationX: 0.14,
      inclinationZ: -0.12,
      speed: 0.12,
      phase: 5.1,
      color: 0xffb844,
      groundHubId: 'HUB_JPN_OKA'
    }
  ];

  const activeSatellites = [];
  for (const cfg of orbitConfigs) {
    const orbitPivot = new THREE.Group();
    orbitPivot.rotation.x = cfg.inclinationX;
    orbitPivot.rotation.z = cfg.inclinationZ;
    satellitesGroup.add(orbitPivot);

    const ringPts = [];
    const segs = 96;
    for (let i = 0; i <= segs; i++) {
      const a = (i / segs) * Math.PI * 2;
      ringPts.push(new THREE.Vector3(Math.cos(a) * cfg.radius, 0, Math.sin(a) * cfg.radius));
    }
    const orbitGeo = new THREE.BufferGeometry().setFromPoints(ringPts);
    const orbitMat = new THREE.LineBasicMaterial({
      color: cfg.color,
      transparent: true,
      opacity: 0.28
    });
    orbitPivot.add(new THREE.Line(orbitGeo, orbitMat));

    const satMesh = createSatellite3DModel(cfg.color);
    orbitPivot.add(satMesh);

    const beamGeo = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(),
      new THREE.Vector3()
    ]);
    const beamMat = new THREE.LineBasicMaterial({
      color: cfg.color,
      transparent: true,
      opacity: 0.36
    });
    const beamLine = new THREE.Line(beamGeo, beamMat);
    satellitesGroup.add(beamLine);

    activeSatellites.push({
      cfg,
      orbitPivot,
      satMesh,
      beamLine,
      angle: cfg.phase
    });
  }

  // --- Camera Spherical Orbit State & CameraDirector Snapshot Support ---
  const camState = {
    Preset: 'GLOBAL_ORBIT',
    targetLon: 135.0,
    targetLat: 25.0,
    targetDistance: 26.2,
    currentLon: 135.0,
    currentLat: 25.0,
    currentDistance: 26.2,
    velLon: 0,
    velLat: 0,
    autoRotate: true,
    isDragging: false,
    lastMouseX: 0,
    lastMouseY: 0,
    trackedSatelliteIdx: 0,
    trackedArcIdx: 0,
    reduceMotion: false,
    lowSpecMode: false
  };

  function setCameraPreset(presetName) {
    camState.Preset = presetName;
    camState.velLon = 0;
    camState.velLat = 0;

    switch (presetName) {
      case 'AUTO':
      case 'GLOBAL_ORBIT':
        camState.autoRotate = true;
        camState.targetLat = 24.0;
        camState.targetLon = 135.0;
        camState.targetDistance = 26.2;
        break;
      case 'GLOBAL':
        camState.autoRotate = false;
        camState.targetLat = 20.0;
        camState.targetLon = 135.0;
        camState.targetDistance = 28.0;
        break;
      case 'JAPAN':
      case 'JAPAN_STRATEGIC':
        camState.autoRotate = false;
        camState.targetLat = 35.8;
        camState.targetLon = 138.5;
        camState.targetDistance = 17.0;
        break;
      case 'PACIFIC':
      case 'PACIFIC_FOCUS':
        camState.autoRotate = false;
        camState.targetLat = 18.0;
        camState.targetLon = -175.0;
        camState.targetDistance = 25.5;
        break;
      case 'ATLANTIC':
      case 'ATLANTIC_FOCUS':
        camState.autoRotate = false;
        camState.targetLat = 28.0;
        camState.targetLon = -38.0;
        camState.targetDistance = 25.0;
        break;
      case 'AMERICAS':
      case 'USA_FOCUS':
        camState.autoRotate = false;
        camState.targetLat = 34.0;
        camState.targetLon = -92.0;
        camState.targetDistance = 21.5;
        break;
      case 'EUROPE':
      case 'EUROPE_FOCUS':
        camState.autoRotate = false;
        camState.targetLat = 48.5;
        camState.targetLon = 10.5;
        camState.targetDistance = 20.0;
        break;
      case 'ASIA_FOCUS':
        camState.autoRotate = false;
        camState.targetLat = 28.0;
        camState.targetLon = 112.0;
        camState.targetDistance = 21.5;
        break;
      case 'SATELLITE_ORBIT':
        camState.autoRotate = false;
        camState.targetDistance = 33.0;
        break;
      case 'ARC_TRACKING':
        camState.autoRotate = false;
        camState.targetDistance = 22.0;
        break;
      default:
        camState.autoRotate = true;
        camState.targetDistance = 26.2;
        break;
    }
  }

  function focusLatLon(lat, lon, distance = 19.5) {
    camState.autoRotate = false;
    camState.targetLat = THREE.MathUtils.clamp(Number(lat) || 0, -78, 78);
    camState.targetLon = Number(lon) || 0;
    camState.targetDistance = THREE.MathUtils.clamp(Number(distance) || 19.5, 14.5, 40.0);
  }

  function saveViewState() {
    return {
      Preset: camState.Preset,
      targetLon: camState.targetLon,
      targetLat: camState.targetLat,
      targetDistance: camState.targetDistance,
      currentLon: camState.currentLon,
      currentLat: camState.currentLat,
      currentDistance: camState.currentDistance,
      autoRotate: camState.autoRotate
    };
  }

  function restoreViewState(snapshot) {
    if (!snapshot) return;
    camState.Preset = snapshot.Preset ?? camState.Preset;
    camState.targetLon = snapshot.targetLon ?? camState.targetLon;
    camState.targetLat = snapshot.targetLat ?? camState.targetLat;
    camState.targetDistance = snapshot.targetDistance ?? camState.targetDistance;
    camState.currentLon = snapshot.currentLon ?? camState.currentLon;
    camState.currentLat = snapshot.currentLat ?? camState.currentLat;
    camState.currentDistance = snapshot.currentDistance ?? camState.currentDistance;
    camState.autoRotate = snapshot.autoRotate ?? camState.autoRotate;
  }

  function setPerformanceOptions({ reduceMotion, lowSpecMode } = {}) {
    if (typeof reduceMotion === 'boolean') camState.reduceMotion = reduceMotion;
    if (typeof lowSpecMode === 'boolean') {
      camState.lowSpecMode = lowSpecMode;
      renderer.setPixelRatio(lowSpecMode || isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
    }
  }

  // --- Mouse Drag & Wheel Zoom Event Listeners ---
  canvasEl.addEventListener('pointerdown', (e) => {
    camState.isDragging = true;
    camState.autoRotate = false;
    camState.lastMouseX = e.clientX;
    camState.lastMouseY = e.clientY;
  });

  window.addEventListener('pointermove', (e) => {
    if (!camState.isDragging) return;
    const dx = e.clientX - camState.lastMouseX;
    const dy = e.clientY - camState.lastMouseY;
    camState.lastMouseX = e.clientX;
    camState.lastMouseY = e.clientY;

    camState.velLon = -dx * 0.26;
    camState.velLat = dy * 0.22;
    camState.targetLon += camState.velLon;
    camState.targetLat = THREE.MathUtils.clamp(camState.targetLat + camState.velLat, -78, 78);
  });

  window.addEventListener('pointerup', () => {
    camState.isDragging = false;
  });

  canvasEl.addEventListener(
    'wheel',
    (e) => {
      e.preventDefault();
      const zoomStep = e.deltaY * 0.014;
      camState.targetDistance = THREE.MathUtils.clamp(camState.targetDistance + zoomStep, 14.2, 42.0);
    },
    { passive: false }
  );

  // --- Right Sidebar Real-Time Route & Target Region Updater ---
  let lastPanelUpdateMs = 0;
  function updateCommandTargetPanel(hub, routeObj) {
    const now = performance.now();
    if (now - lastPanelUpdateMs < 650) return;
    lastPanelUpdateMs = now;

    const realGeoEnabled = Boolean(document.getElementById('chk-v21-real-geo')?.checked);
    const regionEl = document.getElementById('cmd-current-target-region');
    if (regionEl) {
      regionEl.textContent = realGeoEnabled
        ? `${hub.country_ja} · ${hub.city_ja} (${hub.lat.toFixed(2)}°N, ${hub.lon.toFixed(2)}°E)`
        : `防護対象ノード · ${hub.city_ja} (${hub.lat.toFixed(2)}°N, ${hub.lon.toFixed(2)}°E)`;
    }
    const stageEl = document.getElementById('cmd-current-inspection-stage');
    if (stageEl && routeObj) {
      stageEl.textContent = routeObj.inspection_stage_ja;
    }
    const routeLabelEl = document.getElementById('cmd-active-route-label');
    if (routeLabelEl && routeObj) {
      routeLabelEl.textContent = realGeoEnabled
        ? `${routeObj.label_ja} [${routeObj.protocol}]（実在地域表示・攻撃元断定なし）`
        : `Region A-01 → Relay-01 → Relay-02 → JAPAN [${routeObj.protocol}]（架空リージョン既定）`;
    }
    const modeBadgeEl = document.getElementById('cmd-active-route-mode');
    if (modeBadgeEl && routeObj) {
      modeBadgeEl.textContent = routeObj.evidence_mode;
      modeBadgeEl.className =
        routeObj.evidence_mode === 'LIVE OBSERVED'
          ? 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#27E59A]/20 text-[#27E59A] border border-[#27E59A]/40'
          : routeObj.evidence_mode === 'INFERRED'
            ? 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#F5B942]/20 text-[#FFE3A0] border border-[#F5B942]/40'
            : 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#35D9FF]/20 text-[#35D9FF] border border-[#35D9FF]/40';
    }
  }

  function syncViewportSize() {
    const w = canvasEl.clientWidth || 880;
    const h = canvasEl.clientHeight || 560;
    if (canvasEl.width !== w || canvasEl.height !== h) {
      renderer.setSize(w, h, false);
      camera.aspect = w / Math.max(1, h);
      camera.updateProjectionMatrix();
    }
  }

  window.addEventListener('resize', syncViewportSize);
  syncViewportSize();

  let fpsFrameCount = 0;
  let fpsLastSampleTime = performance.now();
  let measuredFps = 60;
  let prevFrameTime = performance.now();

  const tempSatWorldPos = new THREE.Vector3();
  const tempGroundPos = new THREE.Vector3();
  const tempCamDir = new THREE.Vector3();

  function renderLoop(now) {
    requestAnimationFrame(renderLoop);

    const dt = Math.min(0.08, Math.max(0.001, (now - prevFrameTime) / 1000));
    prevFrameTime = now;

    fpsFrameCount += 1;
    const elapsedSample = now - fpsLastSampleTime;
    if (elapsedSample >= 500) {
      measuredFps = Math.max(1, Math.min(144, Math.round((fpsFrameCount * 1000) / elapsedSample)));
      fpsFrameCount = 0;
      fpsLastSampleTime = now;
      const fpsEl = document.getElementById('arena-globe-fps-badge');
      if (fpsEl) fpsEl.textContent = `${measuredFps} FPS`;
      const topFpsEl = document.getElementById('top-status-fps');
      if (topFpsEl) topFpsEl.textContent = `${measuredFps}`;
    }

    syncViewportSize();

    const emergencyMuted = Boolean(window.emergencyOverrideActive);

    // 1. Update Camera Position with Smooth Damping
    if (!emergencyMuted) {
      if (camState.Preset === 'SATELLITE_ORBIT' && activeSatellites.length > 0) {
        const sat = activeSatellites[camState.trackedSatelliteIdx % activeSatellites.length];
        sat.satMesh.getWorldPosition(tempSatWorldPos);
        const spherical = new THREE.Spherical().setFromVector3(tempSatWorldPos);
        camState.targetLat = 90 - THREE.MathUtils.radToDeg(spherical.phi);
        camState.targetLon = THREE.MathUtils.radToDeg(spherical.theta) - 90;
      } else if (camState.Preset === 'ARC_TRACKING' && activeSegmentParticles.length > 0) {
        const seg = activeSegmentParticles[camState.trackedArcIdx % activeSegmentParticles.length];
        const targetHub = seg.targetHub;
        camState.targetLat = targetHub.lat;
        camState.targetLon = targetHub.lon;
      } else if (camState.autoRotate && !camState.isDragging && !camState.reduceMotion) {
        camState.targetLon += dt * 3.8;
      }
    }

    if (!camState.isDragging) {
      camState.velLon *= 0.92;
      camState.velLat *= 0.92;
      camState.targetLon += camState.velLon * 0.25;
      camState.targetLat = THREE.MathUtils.clamp(camState.targetLat + camState.velLat * 0.25, -78, 78);
    }

    const damping = camState.reduceMotion ? 1.0 : 1.0 - Math.exp(-dt * 6.5);
    camState.currentLon += (camState.targetLon - camState.currentLon) * damping;
    camState.currentLat += (camState.targetLat - camState.currentLat) * damping;
    camState.currentDistance += (camState.targetDistance - camState.currentDistance) * damping;

    const camPos = latLonToVector3(camState.currentLat, camState.currentLon, camState.currentDistance);
    camera.position.copy(camPos);
    camera.lookAt(0, 0, 0);
    tempCamDir.copy(camera.position).normalize();

    // 2. Strict Back-of-Earth Occlusion Check for Surface Hub Rings & 12 City Labels (Section 4.3 & 5.2)
    for (let i = 0; i < hubMeshes.length; i++) {
      const hm = hubMeshes[i];
      const facingDot = hm.normal.dot(tempCamDir);
      const visible = facingDot > 0.06;
      hm.coreMesh.visible = visible;
      hm.ringMesh.visible = visible;
      if (visible) {
        const pulse = 1.0 + 0.22 * Math.sin(now * 0.004 + i);
        hm.ringMesh.scale.setScalar(pulse);
      }
    }

    for (let i = 0; i < cityMarkers.length; i++) {
      const cm = cityMarkers[i];
      const facingDot = cm.normal.dot(tempCamDir);
      const visible = facingDot > 0.12;
      cm.dotMesh.visible = visible;
      cm.labelSprite.visible = visible && camState.currentDistance < 32.0;
      if (visible && cm.labelSprite.visible) {
        cm.labelSprite.material.opacity = THREE.MathUtils.clamp((facingDot - 0.12) * 2.4, 0.15, 0.92);
      }
    }

    // 3. Animate Communication Particles along 3D Great-Circle Arcs
    if (!emergencyMuted) {
      for (let i = 0; i < activeSegmentParticles.length; i++) {
        const seg = activeSegmentParticles[i];
        seg.t += dt * seg.speed;
        if (seg.t >= 1.0) {
          seg.t -= 1.0;
          triggerArrivalRippleAtHub(seg.targetHub, seg.route.severity_color, seg.route);
        }

        const pHead = seg.curve.getPointAt(seg.t);
        const pTrail1 = seg.curve.getPointAt(Math.max(0, seg.t - 0.035));
        const pTrail2 = seg.curve.getPointAt(Math.max(0, seg.t - 0.07));

        seg.headMesh.position.copy(pHead);
        seg.trailMesh1.position.copy(pTrail1);
        seg.trailMesh2.position.copy(pTrail2);

        // Hide particles when on the far back side of the globe
        const headFacing = pHead.clone().normalize().dot(tempCamDir) > -0.08;
        seg.headMesh.visible = headFacing;
        seg.trailMesh1.visible = headFacing;
        seg.trailMesh2.visible = headFacing;
      }
    }

    // 4. Animate Concentric Arrival Ripples on Earth Surface with Backface Occlusion
    for (let i = 0; i < arrivalRipplePool.length; i++) {
      const rp = arrivalRipplePool[i];
      if (!rp.active) continue;
      rp.progress += dt * 0.85;
      const onFront = rp.normal.dot(tempCamDir) > 0.04;
      if (rp.progress >= 1.0 || !onFront) {
        if (rp.progress >= 1.0) rp.active = false;
        rp.innerRing.visible = false;
        rp.outerRing.visible = false;
        continue;
      }
      rp.innerRing.visible = true;
      rp.outerRing.visible = true;
      const ease = 1.0 - Math.pow(1.0 - rp.progress, 2.2);
      rp.innerRing.scale.setScalar(1.0 + ease * 2.8);
      rp.outerRing.scale.setScalar(1.0 + ease * 4.2);
      rp.innerMat.opacity = (1.0 - rp.progress) * 0.85;
      rp.outerMat.opacity = Math.max(0, (1.0 - rp.progress * 1.15) * 0.55);
    }

    // 5. Animate 3D Satellites & Ground Station Communication Beams
    for (let i = 0; i < activeSatellites.length; i++) {
      const sat = activeSatellites[i];
      if (!emergencyMuted && !camState.reduceMotion) {
        sat.angle += dt * sat.cfg.speed;
      }
      const sx = Math.cos(sat.angle) * sat.cfg.radius;
      const sz = Math.sin(sat.angle) * sat.cfg.radius;
      sat.satMesh.position.set(sx, 0, sz);
      sat.satMesh.lookAt(0, 0, 0);

      sat.satMesh.getWorldPosition(tempSatWorldPos);
      const groundHub = hubById.get(sat.cfg.groundHubId);
      if (groundHub) {
        tempGroundPos.copy(latLonToVector3(groundHub.lat, groundHub.lon, EARTH_RADIUS * 1.003));
        const posAttr = sat.beamLine.geometry.getAttribute('position');
        posAttr.setXYZ(0, tempSatWorldPos.x, tempSatWorldPos.y, tempSatWorldPos.z);
        posAttr.setXYZ(1, tempGroundPos.x, tempGroundPos.y, tempGroundPos.z);
        posAttr.needsUpdate = true;
      }
    }

    if (!camState.reduceMotion) {
      starField.rotation.y += dt * 0.006;
    }

    renderer.render(scene, camera);
  }

  requestAnimationFrame(renderLoop);

  const api = {
    renderer,
    scene,
    camera,
    setCameraPreset,
    focusLatLon,
    saveViewState,
    restoreViewState,
    setPerformanceOptions,
    getMeasuredFps: () => measuredFps,
    getContinentCount: () => geoData.landmassPolygons.length,
    getRoutesCount: () => geoData.internationalRoutes.length,
    getSatellitesCount: () => activeSatellites.length,
    getCitiesCount: () => MAJOR_12_CITIES.length
  };

  window.ThunderhallEarth3D = api;
  return api;
}
