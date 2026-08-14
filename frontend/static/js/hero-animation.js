/**
 * Premium 3D Hero Animation
 * Blockchain Secure Messaging System
 * Three.js background + CSS message pipeline + particle effects
 */
(function () {
    "use strict";

    const AWARENESS_MESSAGES = [
        "Think Before You Click.",
        "Beware of Phishing Attacks.",
        "Use Strong Passwords.",
        "Enable Multi-Factor Authentication.",
        "Never Share Your OTP.",
        "Verify Unknown Links Before Clicking.",
        "Stay Safe from Cyber Criminals.",
        "Protect Your Digital Identity.",
        "Encrypt Your Conversations.",
        "Cyber Awareness is Your First Line of Defense."
    ];

    const SUCCESS_MESSAGES = [
        "Message Encrypted Successfully",
        "Blockchain Verification Complete",
        "Secure Delivery Confirmed",
        "Integrity Verified",
        "Tamper-Proof Communication"
    ];

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let awarenessIndex = 0;
    let successIndex = 0;
    let threeRenderer = null;
    let threeAnimId = null;
    let particleAnimId = null;

    document.addEventListener("DOMContentLoaded", initHero);

    function initHero() {
        const hero = document.getElementById("cyber-hero");
        if (!hero) return;

        initBinaryRain();
        initParticlesCanvas();
        if (!prefersReducedMotion) {
            initThreeScene();
        }
        initMessagePipeline();

        window.addEventListener("resize", debounce(handleResize, 200));
    }

    /* ---- Binary code rain ---- */
    function initBinaryRain() {
        const container = document.getElementById("hero-binary-rain");
        if (!container || prefersReducedMotion) return;

        const cols = window.innerWidth < 576 ? 6 : 12;
        for (let i = 0; i < cols; i++) {
            const col = document.createElement("div");
            col.className = "hero-binary-column";
            col.style.animationDuration = `${8 + Math.random() * 12}s`;
            col.style.animationDelay = `${Math.random() * 5}s`;
            let bits = "";
            for (let j = 0; j < 40; j++) {
                bits += Math.random() > 0.5 ? "1" : "0";
            }
            col.textContent = bits;
            container.appendChild(col);
        }
    }

    /* ---- 2D floating particles ---- */
    function initParticlesCanvas() {
        const canvas = document.getElementById("hero-particles-canvas");
        if (!canvas || prefersReducedMotion) return;

        const ctx = canvas.getContext("2d");
        let particles = [];
        const count = window.innerWidth < 768 ? 40 : 80;

        function resize() {
            const dpr = devicePixelRatio;
            canvas.width = canvas.offsetWidth * dpr;
            canvas.height = canvas.offsetHeight * dpr;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function createParticles() {
            particles = [];
            const w = canvas.offsetWidth;
            const h = canvas.offsetHeight;
            for (let i = 0; i < count; i++) {
                particles.push({
                    x: Math.random() * w,
                    y: Math.random() * h,
                    vx: (Math.random() - 0.5) * 0.4,
                    vy: (Math.random() - 0.5) * 0.4,
                    r: Math.random() * 2 + 0.5,
                    hue: Math.random() > 0.5 ? 180 : 280
                });
            }
        }

        function draw() {
            const w = canvas.offsetWidth;
            const h = canvas.offsetHeight;
            ctx.clearRect(0, 0, w, h);

            particles.forEach(function (p, i) {
                p.x += p.vx;
                p.y += p.vy;
                if (p.x < 0) p.x = w;
                if (p.x > w) p.x = 0;
                if (p.y < 0) p.y = h;
                if (p.y > h) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
                ctx.fillStyle = "hsla(" + p.hue + ", 100%, 60%, 0.6)";
                ctx.fill();

                for (let j = i + 1; j < particles.length; j++) {
                    const q = particles[j];
                    const dist = Math.hypot(p.x - q.x, p.y - q.y);
                    if (dist < 100) {
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(q.x, q.y);
                        ctx.strokeStyle = "rgba(0, 240, 255, " + (0.08 * (1 - dist / 100)) + ")";
                        ctx.stroke();
                    }
                }
            });

            particleAnimId = requestAnimationFrame(draw);
        }

        resize();
        createParticles();
        draw();

        canvas._heroResize = function () {
            resize();
            createParticles();
        };
    }

    /* ---- Three.js 3D blockchain network ---- */
    function initThreeScene() {
        const canvas = document.getElementById("hero-three-canvas");
        if (!canvas || typeof THREE === "undefined") return;

        const scene = new THREE.Scene();
        scene.fog = new THREE.FogExp2(0x030508, 0.035);

        const camera = new THREE.PerspectiveCamera(
            55,
            canvas.clientWidth / canvas.clientHeight,
            0.1,
            100
        );
        camera.position.set(0, 2, 8);

        threeRenderer = new THREE.WebGLRenderer({
            canvas: canvas,
            alpha: true,
            antialias: true,
            powerPreference: "high-performance"
        });
        threeRenderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        threeRenderer.setSize(canvas.clientWidth, canvas.clientHeight, false);
        threeRenderer.setClearColor(0x000000, 0);

        // Lights
        const ambient = new THREE.AmbientLight(0x112244, 0.6);
        scene.add(ambient);

        const blueLight = new THREE.PointLight(0x00f0ff, 1.2, 20);
        blueLight.position.set(-3, 3, 2);
        scene.add(blueLight);

        const purpleLight = new THREE.PointLight(0x9c27b0, 0.8, 20);
        purpleLight.position.set(3, -1, 3);
        scene.add(purpleLight);

        // Blockchain blocks (3D cubes)
        const blocks = [];
        const blockPositions = [
            [-4, 0.5, -1], [-2.5, -0.8, 0.5], [2.5, 0.3, -0.5],
            [4, -0.5, 0], [-1, 1.2, -1.5], [1, -1, -1],
            [-3.5, -1.2, 1], [3.5, 1, 0.8]
        ];

        blockPositions.forEach(function (pos, idx) {
            const size = 0.35 + (idx % 3) * 0.1;
            const geo = new THREE.BoxGeometry(size, size, size);
            const mat = new THREE.MeshPhysicalMaterial({
                color: idx % 2 === 0 ? 0x00f0ff : 0x9c27b0,
                metalness: 0.6,
                roughness: 0.2,
                transparent: true,
                opacity: 0.75,
                emissive: idx % 2 === 0 ? 0x003344 : 0x220033,
                emissiveIntensity: 0.4
            });
            const mesh = new THREE.Mesh(geo, mat);
            mesh.position.set(pos[0], pos[1], pos[2]);
            mesh.userData = {
                baseY: pos[1],
                speed: 0.3 + idx * 0.08,
                phase: idx * 0.7
            };
            scene.add(mesh);
            blocks.push(mesh);

            const edges = new THREE.EdgesGeometry(geo);
            const line = new THREE.LineSegments(
                edges,
                new THREE.LineBasicMaterial({ color: 0x00f0ff, transparent: true, opacity: 0.5 })
            );
            mesh.add(line);
        });

        // Chain connection lines
        const lineMat = new THREE.LineBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.25
        });
        for (let i = 0; i < blocks.length - 1; i++) {
            const points = [
                blocks[i].position.clone(),
                blocks[i + 1].position.clone()
            ];
            const geo = new THREE.BufferGeometry().setFromPoints(points);
            scene.add(new THREE.Line(geo, lineMat));
        }

        // Central shield torus
        const torusGeo = new THREE.TorusGeometry(1.2, 0.03, 8, 64);
        const torusMat = new THREE.MeshBasicMaterial({
            color: 0x00f0ff,
            transparent: true,
            opacity: 0.35
        });
        const torus = new THREE.Mesh(torusGeo, torusMat);
        torus.rotation.x = Math.PI / 2;
        scene.add(torus);

        const torus2 = torus.clone();
        torus2.scale.set(1.4, 1.4, 1.4);
        torus2.material = torusMat.clone();
        torus2.material.opacity = 0.2;
        scene.add(torus2);

        // Particle field
        const particleCount = 300;
        const pGeo = new THREE.BufferGeometry();
        const positions = new Float32Array(particleCount * 3);
        for (let i = 0; i < particleCount * 3; i++) {
            positions[i] = (Math.random() - 0.5) * 16;
        }
        pGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
        const pMat = new THREE.PointsMaterial({
            color: 0x00f0ff,
            size: 0.04,
            transparent: true,
            opacity: 0.6,
            blending: THREE.AdditiveBlending
        });
        const particleSystem = new THREE.Points(pGeo, pMat);
        scene.add(particleSystem);

        const clock = new THREE.Clock();

        function animate() {
            threeAnimId = requestAnimationFrame(animate);
            const t = clock.getElapsedTime();

            blocks.forEach(function (block) {
                block.rotation.x = t * block.userData.speed * 0.5;
                block.rotation.y = t * block.userData.speed;
                block.position.y = block.userData.baseY + Math.sin(t + block.userData.phase) * 0.15;
            });

            torus.rotation.z = t * 0.3;
            torus2.rotation.z = -t * 0.2;

            particleSystem.rotation.y = t * 0.02;

            camera.position.x = Math.sin(t * 0.15) * 0.5;
            camera.lookAt(0, 0, 0);

            threeRenderer.render(scene, camera);
        }

        animate();
        canvas._heroThree = { camera: camera, renderer: threeRenderer };
    }

    /* ---- Message pipeline animation ---- */
    function initMessagePipeline() {
        const travelEl = document.getElementById("hero-traveling-message");
        const travelText = document.getElementById("travel-bubble-text");
        const leftText = document.getElementById("hero-left-text");
        const rightText = document.getElementById("hero-right-text");

        if (!travelEl || !travelText) return;

        function cycleMessages() {
            if (leftText) {
                leftText.classList.add("fade-out");
                setTimeout(function () {
                    leftText.textContent = AWARENESS_MESSAGES[awarenessIndex];
                    leftText.classList.remove("fade-out");
                }, 300);
            }

            travelText.textContent = AWARENESS_MESSAGES[awarenessIndex];
            awarenessIndex = (awarenessIndex + 1) % AWARENESS_MESSAGES.length;

            if (prefersReducedMotion) {
                if (rightText) {
                    rightText.textContent = SUCCESS_MESSAGES[successIndex];
                    successIndex = (successIndex + 1) % SUCCESS_MESSAGES.length;
                }
                setTimeout(cycleMessages, 4000);
                return;
            }

            travelEl.classList.remove("animating");
            void travelEl.offsetWidth;
            travelEl.classList.add("animating");

            setTimeout(function () {
                if (rightText) {
                    rightText.classList.add("fade-out");
                    setTimeout(function () {
                        rightText.textContent = SUCCESS_MESSAGES[successIndex];
                        rightText.classList.remove("fade-out");
                        successIndex = (successIndex + 1) % SUCCESS_MESSAGES.length;
                    }, 300);
                }
                pulseShield();
            }, 4800);

            setTimeout(cycleMessages, 6500);
        }

        if (leftText) leftText.textContent = AWARENESS_MESSAGES[0];
        if (rightText) rightText.textContent = SUCCESS_MESSAGES[0];
        awarenessIndex = 1;
        successIndex = 1;

        setTimeout(cycleMessages, 1200);
    }

    function pulseShield() {
        const shield = document.querySelector(".hero-shield-body");
        if (!shield) return;
        shield.style.transform = "scale(1.08)";
        shield.style.transition = "transform 0.3s ease";
        setTimeout(function () {
            shield.style.transform = "";
        }, 400);
    }

    function handleResize() {
        const canvas = document.getElementById("hero-three-canvas");
        if (canvas && canvas._heroThree) {
            const w = canvas.clientWidth;
            const h = canvas.clientHeight;
            canvas._heroThree.camera.aspect = w / h;
            canvas._heroThree.camera.updateProjectionMatrix();
            canvas._heroThree.renderer.setSize(w, h, false);
        }

        const pCanvas = document.getElementById("hero-particles-canvas");
        if (pCanvas && pCanvas._heroResize) {
            pCanvas._heroResize();
        }
    }

    function debounce(fn, ms) {
        let timer;
        return function () {
            clearTimeout(timer);
            timer = setTimeout(fn, ms);
        };
    }

    window.addEventListener("beforeunload", function () {
        if (threeAnimId) cancelAnimationFrame(threeAnimId);
        if (particleAnimId) cancelAnimationFrame(particleAnimId);
        if (threeRenderer) threeRenderer.dispose();
    });
})();
