/**
 * THUNDERHALL TESTER — 3D Luxury Glass Dome Gachapon & Rigid-Body Capsule Physics Engine
 * Design System: GLOBAL CYBER DEFENSE COMMAND CENTER (Dedicated Fullscreen Event Scene)
 *
 * Uses Three.js (WebGLRenderer) to render:
 *  - Large transparent glass dome with physical clearcoat & specular highlights
 *  - Brushed metal / dark chrome / royal gold frame & rotating handle
 *  - Exit chute, collection tray & THUNDERHALL emblem plate
 *  - 34 two-tone 3D capsules + Blue Mini-Capsule with rigid-body physics
 *  - Supports rendering onto both the Dedicated Fullscreen Event Scene canvas
 *    and the secondary settings/events preview canvas.
 */
import * as THREE from '/vendor/three/three.module.js';

const DOME_RADIUS = 3.55;
const CAPSULE_RADIUS = 0.42;
const CAPSULE_COUNT = 34;

// Section 9.2 Official 5 Capsule Types
const CAPSULE_PALETTE = [
  { rank: 'GREEN', hex: 0x27e59a, label: 'Green Capsule (Normal)', scale: 1.0 },
  { rank: 'ORANGE', hex: 0xffb844, label: 'Orange Capsule (Chance)', scale: 1.0 },
  { rank: 'RED', hex: 0xff475f, label: 'Red Capsule (Hot)', scale: 1.0 },
  { rank: 'GOLD', hex: 0xf5b942, label: 'Gold Capsule (Jackpot)', scale: 1.05 },
  { rank: 'BLUE', hex: 0x35d9ff, label: 'Blue Mini-Capsule (Sub-Event)', scale: 0.78 }
];

function buildNameplateTexture() {
  const c = document.createElement('canvas');
  c.width = 512;
  c.height = 128;
  const ctx = c.getContext('2d');

  const bg = ctx.createLinearGradient(0, 0, 512, 128);
  bg.addColorStop(0, '#030914');
  bg.addColorStop(0.5, '#091C30');
  bg.addColorStop(1, '#030914');
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, 512, 128);

  ctx.strokeStyle = '#F5B942';
  ctx.lineWidth = 8;
  ctx.strokeRect(8, 8, 496, 112);

  ctx.fillStyle = '#FFE3A0';
  ctx.font = '900 44px "Plus Jakarta Sans", sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('THUNDERHALL', 256, 54);

  ctx.fillStyle = '#35D9FF';
  ctx.font = '700 18px "JetBrains Mono", monospace';
  ctx.fillText('52-EFFECT FULLSCREEN EVENT GACHA', 256, 96);

  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.needsUpdate = true;
  return tex;
}

function createTwoPartCapsuleMesh(colorHex, sharedGeos, sharedMats, scaleFactor = 1.0) {
  const group = new THREE.Group();

  const bottomMat = new THREE.MeshStandardMaterial({
    color: colorHex,
    metalness: 0.45,
    roughness: 0.16
  });
  const bottomMesh = new THREE.Mesh(sharedGeos.bottomHemi, bottomMat);
  group.add(bottomMesh);

  const topMesh = new THREE.Mesh(sharedGeos.topHemi, sharedMats.clearTop);
  group.add(topMesh);

  const bandMesh = new THREE.Mesh(sharedGeos.equatorBand, sharedMats.goldTrim);
  bandMesh.rotation.x = Math.PI / 2;
  group.add(bandMesh);

  const coreMat = new THREE.MeshBasicMaterial({ color: colorHex });
  const coreMesh = new THREE.Mesh(sharedGeos.innerCore, coreMat);
  group.add(coreMesh);

  if (scaleFactor !== 1.0) {
    group.scale.setScalar(scaleFactor);
  }

  return { group, topMesh, bottomMesh, coreMesh, bottomMat, coreMat };
}

export function initThunderhallGachapon3D(canvasEl) {
  if (!canvasEl) return null;

  let activeCanvas = canvasEl;
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas: activeCanvas,
      antialias: true,
      alpha: false,
      powerPreference: 'high-performance'
    });
  } catch (err) {
    console.warn('Gachapon WebGLRenderer fallback:', err);
    return null;
  }

  const gl = renderer.getContext();
  const debugExt = gl.getExtension('WEBGL_debug_renderer_info');
  const glRendererStr = debugExt ? String(gl.getParameter(debugExt.UNMASKED_RENDERER_WEBGL)) : '';
  const isSoftwareGl = /SwiftShader|llvmpipe|Software/i.test(glRendererStr);

  renderer.setPixelRatio(isSoftwareGl ? 1 : Math.min(window.devicePixelRatio || 1, 2));
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.22;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.setClearColor(0x030914, 1.0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(35, 1.2, 0.1, 100);
  camera.position.set(0, -0.35, 13.4);
  camera.lookAt(0, -0.55, 0);

  // Studio Three-Point Lighting (Reference D Luxury Glass & Gold Reflections)
  scene.add(new THREE.AmbientLight(0x8beaff, 1.22));

  const keyLight = new THREE.DirectionalLight(0xffffff, 2.35);
  keyLight.position.set(8, 12, 10);
  scene.add(keyLight);

  const goldWarmLight = new THREE.PointLight(0xffe3a0, 2.8, 28);
  goldWarmLight.position.set(-6, 5, 8);
  scene.add(goldWarmLight);

  const cyanRimLight = new THREE.DirectionalLight(0x35d9ff, 1.6);
  cyanRimLight.position.set(0, -8, -8);
  scene.add(cyanRimLight);

  const machineRoot = new THREE.Group();
  scene.add(machineRoot);

  const darkChromeMat = new THREE.MeshStandardMaterial({
    color: 0x091c30,
    metalness: 0.85,
    roughness: 0.22
  });
  const brushedSteelMat = new THREE.MeshStandardMaterial({
    color: 0x102a42,
    metalness: 0.8,
    roughness: 0.26
  });
  const royalGoldMat = new THREE.MeshStandardMaterial({
    color: 0xf5b942,
    emissive: 0x4a2f08,
    emissiveIntensity: 0.25,
    metalness: 0.9,
    roughness: 0.16
  });
  const cyanGlowMat = new THREE.MeshBasicMaterial({
    color: 0x35d9ff,
    transparent: true,
    opacity: 0.72
  });

  const domeCenterY = 1.25;

  // 1. Upper Crown Cap & Finial
  const crownGeo = new THREE.CylinderGeometry(1.4, 2.38, 0.64, 36);
  const crownMesh = new THREE.Mesh(crownGeo, darkChromeMat);
  crownMesh.position.set(0, domeCenterY + DOME_RADIUS - 0.12, 0);
  machineRoot.add(crownMesh);

  const crownGoldRingGeo = new THREE.TorusGeometry(2.35, 0.085, 16, 48);
  const crownGoldRing = new THREE.Mesh(crownGoldRingGeo, royalGoldMat);
  crownGoldRing.rotation.x = Math.PI / 2;
  crownGoldRing.position.set(0, domeCenterY + DOME_RADIUS - 0.38, 0);
  machineRoot.add(crownGoldRing);

  const finialGeo = new THREE.SphereGeometry(0.34, 20, 20);
  const finial = new THREE.Mesh(finialGeo, royalGoldMat);
  finial.position.set(0, domeCenterY + DOME_RADIUS + 0.36, 0);
  machineRoot.add(finial);

  // 2. Central Internal Stirrer Column
  const columnGeo = new THREE.CylinderGeometry(0.28, 0.38, DOME_RADIUS * 1.65, 24);
  const columnMesh = new THREE.Mesh(columnGeo, royalGoldMat);
  columnMesh.position.set(0, domeCenterY - 0.2, 0);
  machineRoot.add(columnMesh);

  // 3. Equator Base Ring
  const baseCollarGeo = new THREE.CylinderGeometry(DOME_RADIUS * 0.88, DOME_RADIUS * 0.94, 0.55, 40);
  const baseCollar = new THREE.Mesh(baseCollarGeo, brushedSteelMat);
  baseCollar.position.set(0, domeCenterY - DOME_RADIUS + 0.35, 0);
  machineRoot.add(baseCollar);

  const baseGoldTorus = new THREE.Mesh(new THREE.TorusGeometry(DOME_RADIUS * 0.91, 0.09, 16, 48), royalGoldMat);
  baseGoldTorus.rotation.x = Math.PI / 2;
  baseGoldTorus.position.set(0, domeCenterY - DOME_RADIUS + 0.62, 0);
  machineRoot.add(baseGoldTorus);

  const baseCyanTorus = new THREE.Mesh(new THREE.TorusGeometry(DOME_RADIUS * 0.93, 0.038, 12, 48), cyanGlowMat);
  baseCyanTorus.rotation.x = Math.PI / 2;
  baseCyanTorus.position.set(0, domeCenterY - DOME_RADIUS + 0.48, 0);
  machineRoot.add(baseCyanTorus);

  // 4. Lower Pedestal Body, THUNDERHALL Nameplate, Handle & Collection Tray
  const bodyGeo = new THREE.CylinderGeometry(2.85, 3.15, 2.85, 36);
  const bodyMesh = new THREE.Mesh(bodyGeo, darkChromeMat);
  bodyMesh.position.set(0, -3.15, 0);
  machineRoot.add(bodyMesh);

  const pedestalBaseGeo = new THREE.CylinderGeometry(3.35, 3.5, 0.42, 36);
  const pedestalBase = new THREE.Mesh(pedestalBaseGeo, royalGoldMat);
  pedestalBase.position.set(0, -4.65, 0);
  machineRoot.add(pedestalBase);

  const plateTex = buildNameplateTexture();
  const plateGeo = new THREE.PlaneGeometry(2.65, 0.66);
  const plateMat = new THREE.MeshBasicMaterial({ map: plateTex });
  const plateMesh = new THREE.Mesh(plateGeo, plateMat);
  plateMesh.position.set(0, -2.15, 2.98);
  machineRoot.add(plateMesh);

  const handlePivot = new THREE.Group();
  handlePivot.position.set(0, -3.05, 3.02);
  machineRoot.add(handlePivot);

  const dialPlate = new THREE.Mesh(new THREE.CylinderGeometry(0.68, 0.68, 0.16, 28), brushedSteelMat);
  dialPlate.rotation.x = Math.PI / 2;
  handlePivot.add(dialPlate);

  const dialGoldRing = new THREE.Mesh(new THREE.TorusGeometry(0.68, 0.055, 14, 32), royalGoldMat);
  handlePivot.add(dialGoldRing);

  const handleBar = new THREE.Mesh(new THREE.BoxGeometry(1.18, 0.22, 0.24), royalGoldMat);
  handleBar.position.set(0, 0, 0.14);
  handlePivot.add(handleBar);

  const trayGroup = new THREE.Group();
  trayGroup.position.set(0, -4.15, 3.12);
  machineRoot.add(trayGroup);

  const chuteHole = new THREE.Mesh(
    new THREE.BoxGeometry(1.25, 0.72, 0.45),
    new THREE.MeshBasicMaterial({ color: 0x030914 })
  );
  trayGroup.add(chuteHole);

  const trayRim = new THREE.Mesh(new THREE.BoxGeometry(1.48, 0.18, 0.68), royalGoldMat);
  trayRim.position.set(0, -0.34, 0.12);
  trayGroup.add(trayRim);

  // 5. Rigid-Body Capsules Inside the Glass Dome
  const capsulesContainer = new THREE.Group();
  capsulesContainer.position.set(0, domeCenterY, 0);
  machineRoot.add(capsulesContainer);

  const sharedGeos = {
    bottomHemi: new THREE.SphereGeometry(CAPSULE_RADIUS, 18, 12, 0, Math.PI * 2, Math.PI / 2, Math.PI / 2),
    topHemi: new THREE.SphereGeometry(CAPSULE_RADIUS, 18, 12, 0, Math.PI * 2, 0, Math.PI / 2),
    equatorBand: new THREE.TorusGeometry(CAPSULE_RADIUS * 0.99, 0.032, 10, 24),
    innerCore: new THREE.SphereGeometry(CAPSULE_RADIUS * 0.48, 12, 12)
  };
  const sharedMats = {
    clearTop: new THREE.MeshPhysicalMaterial({
      color: 0xffffff,
      transparent: true,
      opacity: 0.44,
      roughness: 0.06,
      metalness: 0.05,
      clearcoat: 1.0
    }),
    goldTrim: royalGoldMat
  };

  const capsules = [];
  const innerLimitR = DOME_RADIUS - CAPSULE_RADIUS - 0.16;

  for (let i = 0; i < CAPSULE_COUNT; i++) {
    const pal = CAPSULE_PALETTE[i % CAPSULE_PALETTE.length];
    const parts = createTwoPartCapsuleMesh(pal.hex, sharedGeos, sharedMats, pal.scale);

    const angle = (i / CAPSULE_COUNT) * Math.PI * 2 + (i % 3) * 0.4;
    const rad = (0.25 + ((i * 17) % 70) / 100) * innerLimitR * 0.82;
    const px = Math.cos(angle) * rad;
    const pz = Math.sin(angle) * rad;
    const py = -innerLimitR * 0.55 + (i % 5) * 0.36;

    parts.group.position.set(px, py, pz);
    parts.group.rotation.set(Math.random() * Math.PI, Math.random() * Math.PI, Math.random() * Math.PI);
    capsulesContainer.add(parts.group);

    capsules.push({
      mesh: parts.group,
      pos: new THREE.Vector3(px, py, pz),
      vel: new THREE.Vector3((Math.random() - 0.5) * 1.5, (Math.random() - 0.5) * 1.2, (Math.random() - 0.5) * 1.5),
      angVel: new THREE.Vector3((Math.random() - 0.5) * 3, (Math.random() - 0.5) * 3, (Math.random() - 0.5) * 3),
      colorHex: pal.hex,
      rank: pal.rank
    });
  }

  // 6. Ejected / Opened Prize Capsule in Collection Tray + Sub Blue Mini-Capsule
  const prizeCapsuleParts = createTwoPartCapsuleMesh(0x27e59a, sharedGeos, sharedMats, 1.38);
  const prizeCapsuleGroup = prizeCapsuleParts.group;
  prizeCapsuleGroup.visible = false;
  machineRoot.add(prizeCapsuleGroup);

  const miniBlueParts = createTwoPartCapsuleMesh(0x35d9ff, sharedGeos, sharedMats, 0.85);
  const miniBlueGroup = miniBlueParts.group;
  miniBlueGroup.visible = false;
  machineRoot.add(miniBlueGroup);

  // 7. Large Transparent Glass Dome
  const domeGeo = new THREE.SphereGeometry(DOME_RADIUS, 48, 36);
  const domeGlassMat = new THREE.MeshPhysicalMaterial({
    color: 0xd8f3ff,
    transparent: true,
    opacity: 0.21,
    roughness: 0.04,
    metalness: 0.08,
    clearcoat: 1.0,
    clearcoatRoughness: 0.03,
    depthWrite: false
  });
  const domeMesh = new THREE.Mesh(domeGeo, domeGlassMat);
  domeMesh.position.set(0, domeCenterY, 0);
  domeMesh.renderOrder = 10;
  machineRoot.add(domeMesh);

  const domeRimGeo = new THREE.SphereGeometry(DOME_RADIUS * 1.004, 48, 36);
  const domeRimMat = new THREE.ShaderMaterial({
    uniforms: {
      rimColor: { value: new THREE.Color(0x35d9ff) },
      goldColor: { value: new THREE.Color(0xffe3a0) }
    },
    vertexShader: `
      varying vec3 vNormal;
      varying vec3 vViewPosition;
      void main() {
        vNormal = normalize(normalMatrix * normal);
        vec4 mvPos = modelViewMatrix * vec4(position, 1.0);
        vViewPosition = -mvPos.xyz;
        gl_Position = projectionMatrix * mvPos;
      }
    `,
    fragmentShader: `
      uniform vec3 rimColor;
      uniform vec3 goldColor;
      varying vec3 vNormal;
      varying vec3 vViewPosition;
      void main() {
        vec3 viewDir = normalize(vViewPosition);
        float rim = 1.0 - max(0.0, dot(viewDir, vNormal));
        float spec = pow(rim, 3.4) * 0.64;
        vec3 col = mix(rimColor, goldColor, 0.28);
        gl_FragColor = vec4(col, spec);
      }
    `,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false
  });
  const domeRimMesh = new THREE.Mesh(domeRimGeo, domeRimMat);
  domeRimMesh.position.set(0, domeCenterY, 0);
  domeRimMesh.renderOrder = 11;
  machineRoot.add(domeRimMesh);

  // Optional Secondary Fullscreen Mirror Canvas (copies WebGL frame onto #fullscreen-gachapon-canvas when active)
  const spinState = {
    active: false,
    timer: 0,
    duration: 2.3,
    rankColorHex: 0x27e59a,
    prizeDropProgress: 0,
    prizeOpening: false,
    hasMiniBlue: false
  };

  function triggerSpinAnimation(rankStr, includeMiniBlue = true) {
    if (window.emergencyOverrideActive) return;
    const rankMap = {
      GREEN: 0x27e59a,
      ORANGE: 0xffb844,
      RED: 0xff475f,
      GOLD: 0xf5b942,
      BLUE: 0x35d9ff
    };
    const hex = rankMap[rankStr] || 0x35d9ff;
    spinState.active = true;
    spinState.timer = spinState.duration;
    spinState.rankColorHex = hex;
    spinState.prizeDropProgress = 0;
    spinState.prizeOpening = true;
    spinState.hasMiniBlue = includeMiniBlue;

    prizeCapsuleParts.bottomMat.color.setHex(hex);
    prizeCapsuleParts.coreMat.color.setHex(hex);
    prizeCapsuleGroup.visible = true;
    prizeCapsuleParts.topMesh.position.set(0, 0, 0);
    prizeCapsuleParts.topMesh.rotation.set(0, 0, 0);

    miniBlueGroup.visible = Boolean(includeMiniBlue);

    for (let i = 0; i < capsules.length; i++) {
      const c = capsules[i];
      c.vel.set(
        (Math.random() - 0.5) * 15.0,
        5.0 + Math.random() * 10.0,
        (Math.random() - 0.5) * 15.0
      );
      c.angVel.set(
        (Math.random() - 0.5) * 13.0,
        (Math.random() - 0.5) * 13.0,
        (Math.random() - 0.5) * 13.0
      );
    }
  }

  function syncSize() {
    const w = activeCanvas.clientWidth || 380;
    const h = activeCanvas.clientHeight || 340;
    if (activeCanvas.width !== w || activeCanvas.height !== h) {
      renderer.setSize(w, h, false);
      camera.aspect = w / Math.max(1, h);
      camera.updateProjectionMatrix();
    }
  }

  window.addEventListener('resize', syncSize);
  syncSize();

  let prevTime = performance.now();
  const diffVec = new THREE.Vector3();
  const normalVec = new THREE.Vector3();

  function stepRigidBodyPhysics(dt) {
    if (window.emergencyOverrideActive) return;

    const gravityY = -15.5;
    const restitution = 0.7;
    const wallFriction = 0.96;
    const minDist = CAPSULE_RADIUS * 2.0;
    const minDistSq = minDist * minDist;

    for (let i = 0; i < capsules.length; i++) {
      const c = capsules[i];
      c.vel.y += gravityY * dt;

      if (spinState.timer > 0) {
        c.vel.x += -c.pos.z * 10.2 * dt;
        c.vel.z += c.pos.x * 10.2 * dt;
        c.vel.y += 4.5 * dt;
      } else {
        if (c.pos.y < -innerLimitR * 0.72 && Math.random() < 0.03) {
          c.vel.y += 2.6;
          c.vel.x += (Math.random() - 0.5) * 1.8;
          c.vel.z += (Math.random() - 0.5) * 1.8;
        }
      }

      c.pos.addScaledVector(c.vel, dt);

      const dist = c.pos.length();
      if (dist > innerLimitR) {
        normalVec.copy(c.pos).divideScalar(dist);
        c.pos.copy(normalVec).multiplyScalar(innerLimitR);
        const vDotN = c.vel.dot(normalVec);
        if (vDotN > 0) {
          c.vel.addScaledVector(normalVec, -(1 + restitution) * vDotN);
          c.vel.multiplyScalar(wallFriction);
        }
      }

      const horizDist = Math.hypot(c.pos.x, c.pos.z);
      const minPillarDist = 0.36 + CAPSULE_RADIUS;
      if (horizDist < minPillarDist && horizDist > 0.0001) {
        const nx = c.pos.x / horizDist;
        const nz = c.pos.z / horizDist;
        c.pos.x = nx * minPillarDist;
        c.pos.z = nz * minPillarDist;
        const vn = c.vel.x * nx + c.vel.z * nz;
        if (vn < 0) {
          c.vel.x -= 1.65 * vn * nx;
          c.vel.z -= 1.65 * vn * nz;
        }
      }

      c.mesh.position.copy(c.pos);
      c.mesh.rotation.x += c.angVel.x * dt;
      c.mesh.rotation.y += c.angVel.y * dt;
      c.mesh.rotation.z += c.angVel.z * dt;
      c.angVel.multiplyScalar(0.992);
    }

    for (let i = 0; i < capsules.length; i++) {
      const a = capsules[i];
      for (let j = i + 1; j < capsules.length; j++) {
        const b = capsules[j];
        diffVec.subVectors(b.pos, a.pos);
        const dSq = diffVec.lengthSq();
        if (dSq < minDistSq && dSq > 0.00001) {
          const d = Math.sqrt(dSq);
          const overlap = (minDist - d) * 0.5;
          diffVec.divideScalar(d);

          a.pos.addScaledVector(diffVec, -overlap);
          b.pos.addScaledVector(diffVec, overlap);

          const relVelX = b.vel.x - a.vel.x;
          const relVelY = b.vel.y - a.vel.y;
          const relVelZ = b.vel.z - a.vel.z;
          const sepVel = relVelX * diffVec.x + relVelY * diffVec.y + relVelZ * diffVec.z;

          if (sepVel < 0) {
            const impulse = -(1 + 0.65) * sepVel * 0.5;
            a.vel.addScaledVector(diffVec, -impulse);
            b.vel.addScaledVector(diffVec, impulse);
          }
        }
      }
    }

    if (spinState.timer > 0) {
      spinState.timer = Math.max(0, spinState.timer - dt);
      handlePivot.rotation.z -= dt * 8.0;
    }

    if (spinState.prizeOpening) {
      spinState.prizeDropProgress = Math.min(1.0, spinState.prizeDropProgress + dt * 0.72);
      const p = spinState.prizeDropProgress;

      if (p < 0.45) {
        const t = p / 0.45;
        prizeCapsuleGroup.position.set(0, -2.5 - t * 1.55, 2.2 + t * 1.45);
        prizeCapsuleGroup.rotation.set(t * 2.2, t * 3.1, 0);
        if (spinState.hasMiniBlue) {
          miniBlueGroup.position.set(0.85, -2.6 - t * 1.4, 2.1 + t * 1.35);
          miniBlueGroup.rotation.set(-t * 2.5, t * 2.8, 0);
        }
      } else {
        const openT = (p - 0.45) / 0.55;
        prizeCapsuleGroup.position.set(0, -4.05 + Math.sin(openT * Math.PI) * 0.25, 3.68);
        prizeCapsuleGroup.rotation.set(0.2, openT * Math.PI * 1.5, 0);
        prizeCapsuleParts.topMesh.position.y = openT * 0.55;
        prizeCapsuleParts.topMesh.rotation.z = openT * 0.68;

        if (spinState.hasMiniBlue) {
          miniBlueGroup.position.set(0.95, -3.95 + Math.sin(openT * Math.PI) * 0.18, 3.55);
          miniBlueGroup.rotation.set(0.15, -openT * Math.PI * 1.2, 0);
          miniBlueParts.topMesh.position.y = openT * 0.42;
        }
      }
    }
  }

  function animateGachapon(now) {
    requestAnimationFrame(animateGachapon);
    const dt = Math.min(0.05, Math.max(0.001, (now - prevTime) / 1000));
    prevTime = now;

    syncSize();
    stepRigidBodyPhysics(dt);

    machineRoot.rotation.y = Math.sin(now * 0.0006) * 0.14;

    renderer.render(scene, camera);

    // Mirror onto dedicated fullscreen gachapon canvas if visible
    const fsCanvas = document.getElementById('fullscreen-gachapon-canvas');
    if (fsCanvas && fsCanvas !== activeCanvas && !fsCanvas.closest('.hidden')) {
      const fW = fsCanvas.clientWidth || 640;
      const fH = fsCanvas.clientHeight || 520;
      if (fsCanvas.width !== fW || fsCanvas.height !== fH) {
        fsCanvas.width = fW;
        fsCanvas.height = fH;
      }
      const ctx2d = fsCanvas.getContext('2d');
      if (ctx2d) {
        ctx2d.clearRect(0, 0, fW, fH);
        ctx2d.drawImage(activeCanvas, 0, 0, fW, fH);
      }
    }
  }

  requestAnimationFrame(animateGachapon);

  const api = {
    renderer,
    scene,
    camera,
    triggerSpinAnimation,
    getCapsuleCount: () => capsules.length,
    getPaletteRanks: () => CAPSULE_PALETTE.map((p) => p.rank)
  };

  window.ThunderhallGachapon3D = api;
  return api;
}
