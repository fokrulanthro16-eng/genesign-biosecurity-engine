/**
 * GeneSign - Photorealistic 3D Double-Helix Canvas (Three.js)
 * High-End Behance Aesthetic: Glossy Coral & Cream Strands, Base-Pair Rungs,
 * Floating Molecular Clusters, and Studio Rim-Lighting with Mouse Parallax.
 */

(function () {
  let scene, camera, renderer;
  let helixGroup, moleculesGroup;
  let mouseX = 0, mouseY = 0;
  let targetRotX = 0, targetRotY = 0;
  let windowHalfX = window.innerWidth / 2;
  let windowHalfY = window.innerHeight / 2;

  function init() {
    const canvas = document.getElementById("dna-canvas");
    if (!canvas) return;

    // 1. Scene & Camera
    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x080c14, 0.022);

    camera = new THREE.PerspectiveCamera(
      45,
      window.innerWidth / window.innerHeight,
      0.1,
      100
    );
    camera.position.set(0, 0, 22);

    // 2. Renderer
    renderer = new THREE.WebGLRenderer({
      canvas: canvas,
      antialias: true,
      alpha: true,
      powerPreference: "high-performance",
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.25;

    // 3. Lighting: Cinematic Studio Rim & Key Lights
    const ambientLight = new THREE.AmbientLight(0x0e172a, 1.4);
    scene.add(ambientLight);

    // Warm Key Light (Coral)
    const keyLight = new THREE.DirectionalLight(0xff7744, 2.8);
    keyLight.position.set(12, 16, 14);
    scene.add(keyLight);

    // Cool Rim Light (Cyan Bloom)
    const rimLight = new THREE.DirectionalLight(0x00f2fe, 3.2);
    rimLight.position.set(-14, -8, -12);
    scene.add(rimLight);

    // Soft Top Fill Light
    const fillLight = new THREE.DirectionalLight(0x94a3b8, 1.2);
    fillLight.position.set(0, 20, 0);
    scene.add(fillLight);

    // Glowing Central Point Light
    const coreLight = new THREE.PointLight(0x06b6d4, 1.5, 30);
    coreLight.position.set(0, 0, 2);
    scene.add(coreLight);

    // 4. Construct Procedural 3D Double-Helix
    helixGroup = new THREE.Group();
    buildDoubleHelix(helixGroup);
    scene.add(helixGroup);

    // 5. Construct Orbiting Molecular Clusters
    moleculesGroup = new THREE.Group();
    buildMolecularClusters(moleculesGroup);
    scene.add(moleculesGroup);

    // 6. Event Listeners
    window.addEventListener("resize", onWindowResize);
    window.addEventListener("mousemove", onMouseMove);

    // Initial slight angle
    helixGroup.rotation.z = -0.22;
    helixGroup.rotation.x = 0.15;

    animate();
  }

  function buildDoubleHelix(group) {
    const turns = 3.2;
    const height = 26;
    const radius = 3.6;
    const segments = 160;
    const rungsCount = 42;

    const strand1Points = [];
    const strand2Points = [];

    for (let i = 0; i <= segments; i++) {
      const t = (i / segments) * turns * Math.PI * 2;
      const y = (i / segments) * height - height / 2;

      // Strand 1: Coral
      const x1 = Math.cos(t) * radius;
      const z1 = Math.sin(t) * radius;
      strand1Points.push(new THREE.Vector3(x1, y, z1));

      // Strand 2: Cream/Ivory (Phase shifted by PI)
      const x2 = Math.cos(t + Math.PI) * radius;
      const z2 = Math.sin(t + Math.PI) * radius;
      strand2Points.push(new THREE.Vector3(x2, y, z2));
    }

    const curve1 = new THREE.CatmullRomCurve3(strand1Points);
    const curve2 = new THREE.CatmullRomCurve3(strand2Points);

    // Materials
    // Strand 1: Glossy Vibrant Coral / Orange
    const strand1Mat = new THREE.MeshStandardMaterial({
      color: 0xff5a36,
      emissive: 0x441005,
      roughness: 0.18,
      metalness: 0.35,
    });

    // Strand 2: Cream / Ivory Organic Gloss
    const strand2Mat = new THREE.MeshStandardMaterial({
      color: 0xf5eedc,
      emissive: 0x221c16,
      roughness: 0.22,
      metalness: 0.12,
    });

    const tubeGeo1 = new THREE.TubeGeometry(curve1, 140, 0.38, 16, false);
    const tubeGeo2 = new THREE.TubeGeometry(curve2, 140, 0.38, 16, false);

    const tube1 = new THREE.Mesh(tubeGeo1, strand1Mat);
    const tube2 = new THREE.Mesh(tubeGeo2, strand2Mat);
    group.add(tube1);
    group.add(tube2);

    // End Spheres
    const endSphereGeo = new THREE.SphereGeometry(0.48, 16, 16);
    const s1Start = new THREE.Mesh(endSphereGeo, strand1Mat);
    s1Start.position.copy(strand1Points[0]);
    const s1End = new THREE.Mesh(endSphereGeo, strand1Mat);
    s1End.position.copy(strand1Points[strand1Points.length - 1]);
    group.add(s1Start);
    group.add(s1End);

    const s2Start = new THREE.Mesh(endSphereGeo, strand2Mat);
    s2Start.position.copy(strand2Points[0]);
    const s2End = new THREE.Mesh(endSphereGeo, strand2Mat);
    s2End.position.copy(strand2Points[strand2Points.length - 1]);
    group.add(s2Start);
    group.add(s2End);

    // Base-Pair Rungs
    const phosphorColors = [0x00f2fe, 0x10b981, 0xff7744, 0xf59e0b];
    const rungSphereGeo = new THREE.SphereGeometry(0.24, 12, 12);

    for (let j = 0; j < rungsCount; j++) {
      const u = j / (rungsCount - 1);
      const p1 = curve1.getPointAt(u);
      const p2 = curve2.getPointAt(u);
      const mid = new THREE.Vector3().addVectors(p1, p2).multiplyScalar(0.5);

      const color1 = phosphorColors[j % phosphorColors.length];
      const color2 = phosphorColors[(j + 2) % phosphorColors.length];

      const rungMat1 = new THREE.MeshStandardMaterial({
        color: color1,
        emissive: color1,
        emissiveIntensity: 0.35,
        roughness: 0.25,
        metalness: 0.8,
      });

      const rungMat2 = new THREE.MeshStandardMaterial({
        color: color2,
        emissive: color2,
        emissiveIntensity: 0.35,
        roughness: 0.25,
        metalness: 0.8,
      });

      // Half-cylinder 1 (P1 -> Mid)
      const cylGeo1 = createCylinderBetweenPoints(p1, mid, 0.14);
      const cyl1 = new THREE.Mesh(cylGeo1, rungMat1);
      group.add(cyl1);

      // Half-cylinder 2 (Mid -> P2)
      const cylGeo2 = createCylinderBetweenPoints(mid, p2, 0.14);
      const cyl2 = new THREE.Mesh(cylGeo2, rungMat2);
      group.add(cyl2);

      // Center hydrogen bond connector bead
      const bead = new THREE.Mesh(rungSphereGeo, new THREE.MeshStandardMaterial({
        color: 0xffffff,
        emissive: 0x94a3b8,
        emissiveIntensity: 0.5,
        roughness: 0.1,
        metalness: 0.9,
      }));
      bead.position.copy(mid);
      group.add(bead);
    }
  }

  function createCylinderBetweenPoints(p1, p2, radius) {
    const dist = p1.distanceTo(p2);
    const geo = new THREE.CylinderGeometry(radius, radius, dist, 12);
    geo.translate(0, dist / 2, 0);
    geo.rotateX(Math.PI / 2);

    const helper = new THREE.Object3D();
    helper.position.copy(p1);
    helper.lookAt(p2);
    geo.applyMatrix4(helper.matrix);
    return geo;
  }

  function buildMolecularClusters(group) {
    const particleCount = 55;
    const sphereGeo = new THREE.SphereGeometry(1, 16, 16);

    const clusterColors = [0x00f2fe, 0xff7744, 0x10b981, 0xffffff];

    for (let i = 0; i < particleCount; i++) {
      const col = clusterColors[i % clusterColors.length];
      const mat = new THREE.MeshStandardMaterial({
        color: col,
        emissive: col,
        emissiveIntensity: 0.4,
        roughness: 0.15,
        metalness: 0.7,
        transparent: true,
        opacity: 0.65 + Math.random() * 0.25,
      });

      const scale = 0.12 + Math.random() * 0.28;
      const mesh = new THREE.Mesh(sphereGeo, mat);
      mesh.scale.set(scale, scale, scale);

      // Position in orbital cylindrical cloud around helix
      const angle = Math.random() * Math.PI * 2;
      const dist = 4.5 + Math.random() * 4.5;
      const y = (Math.random() - 0.5) * 24;

      mesh.position.set(
        Math.cos(angle) * dist,
        y,
        Math.sin(angle) * dist
      );

      mesh.userData = {
        angle: angle,
        dist: dist,
        y: y,
        speed: (Math.random() * 0.008 + 0.003) * (Math.random() > 0.5 ? 1 : -1),
        bobSpeed: Math.random() * 0.02 + 0.01,
      };

      group.add(mesh);
    }
  }

  function onMouseMove(event) {
    mouseX = (event.clientX - windowHalfX) / windowHalfX;
    mouseY = (event.clientY - windowHalfY) / windowHalfY;
    targetRotY = mouseX * 0.65;
    targetRotX = mouseY * 0.35;
  }

  function onWindowResize() {
    windowHalfX = window.innerWidth / 2;
    windowHalfY = window.innerHeight / 2;
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
  }

  let clock = new THREE.Clock();

  function animate() {
    requestAnimationFrame(animate);

    const delta = clock.getDelta();
    const time = clock.getElapsedTime();

    // Constant slow majestic rotation + mouse inertia
    if (helixGroup) {
      helixGroup.rotation.y += 0.006;
      helixGroup.rotation.y += (targetRotY - helixGroup.rotation.y * 0.2) * 0.03;
      helixGroup.rotation.x += (targetRotX + 0.15 - helixGroup.rotation.x) * 0.03;

      // Undulating subtle float
      helixGroup.position.y = Math.sin(time * 0.7) * 0.35;
    }

    // Orbiting particles
    if (moleculesGroup) {
      moleculesGroup.children.forEach((p) => {
        p.userData.angle += p.userData.speed;
        p.position.x = Math.cos(p.userData.angle) * p.userData.dist;
        p.position.z = Math.sin(p.userData.angle) * p.userData.dist;
        p.position.y = p.userData.y + Math.sin(time * p.userData.bobSpeed) * 0.5;
      });
    }

    renderer.render(scene, camera);
  }

  window.initDNAViewer = init;
})();
