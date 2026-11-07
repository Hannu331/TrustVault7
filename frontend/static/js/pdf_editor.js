
(() => {
    "use strict";

    // ==================================================
    // CONFIGURATION
    // ==================================================

    const pdfUrl = window.TRUSTVAULT_PDF_URL;
    const documentId = window.TRUSTVAULT_DOCUMENT_ID;

    const pdfCanvas = document.getElementById("pdfCanvas");
    const overlay = document.getElementById("editorOverlay");
    const pdfPage = document.getElementById("pdfPage");
    const status = document.getElementById("editorStatus");
    const thumbnails = document.getElementById("pageThumbnails");

    if (!pdfCanvas || !overlay || !pdfPage || !status || !thumbnails) {
        console.error("PDF editor HTML elements are missing.");
        return;
    }

    const ctx = pdfCanvas.getContext("2d");
    const overlayCtx = overlay.getContext("2d");

    let pdfDocument = null;
    let loadingTask = null;
    let currentPage = 1;
    let zoom = 1;
    let rotation = 0;
    let selectedTool = "select";
    let pendingOperations = [];
    let uploadedImage = null;
    let currentViewport = null;

    const toolButtons = document.querySelectorAll("[data-tool]");

    const pageNumberInput = document.getElementById("pageNumber");
    const previousPageButton = document.getElementById("previousPageButton");
    const nextPageButton = document.getElementById("nextPageButton");
    const zoomLevel = document.getElementById("zoomLevel");
    const rotatePageButton = document.getElementById("rotatePageButton");
    const addPageButton = document.getElementById("addPageButton");
    const deletePageButton = document.getElementById("deletePageButton");
    const insertPageButton = document.getElementById("insertPageButton");
    const imageInput = document.getElementById("imageInput");
    const savePdfButton = document.getElementById("savePdfButton");

    const toolText = document.getElementById("toolText");
    const fontSizeInput = document.getElementById("fontSize");

    if (!window.pdfjsLib) {
        setStatus("PDF.js failed to load.");
        return;
    }

    if (!pdfUrl || !documentId) {
        setStatus("PDF editor configuration is missing.");
        return;
    }

    pdfjsLib.GlobalWorkerOptions.workerSrc =
        "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js";

    function setStatus(message) {
        status.textContent = message;
    }

    // ==================================================
    // API REQUEST
    // ==================================================

    async function apiRequest(url, options = {}) {
        const response = await fetch(url, {
            credentials: "same-origin",
            ...options
        });

        let data = {};

        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (!response.ok) {
            throw new Error(
                data.detail ||
                data.error ||
                data.message ||
                `Request failed (${response.status})`
            );
        }

        return data;
    }

    // ==================================================
    // TOOL SELECTION
    // ==================================================

    function setTool(tool) {
        selectedTool = tool;

        toolButtons.forEach(button => {
            button.classList.toggle(
                "active",
                button.dataset.tool === tool
            );
        });

        setStatus(`Selected tool: ${tool}`);
    }

    toolButtons.forEach(button => {
        button.addEventListener("click", () => {
            setTool(button.dataset.tool);
        });
    });

    // ==================================================
    // LOAD PDF
    // ==================================================

    async function openPdf(url) {
        loadingTask = pdfjsLib.getDocument({
            url,
            withCredentials: true
        });

        pdfDocument = await loadingTask.promise;
    }

    async function loadPdf() {
        try {
            setStatus("Loading PDF...");

            await openPdf(pdfUrl);

            if (pageNumberInput) {
                pageNumberInput.min = 1;
                pageNumberInput.max = pdfDocument.numPages;
            }

            await renderThumbnails();
            await renderPage(1);

            setStatus(`PDF loaded · ${pdfDocument.numPages} pages`);

        } catch (error) {
            console.error(error);
            setStatus(`Could not load PDF: ${error.message}`);
        }
    }

    // ==================================================
    // RENDER PDF PAGE
    // ==================================================

    async function renderPage(pageNumber) {
        if (!pdfDocument) return;

        pageNumber = Math.max(
            1,
            Math.min(pageNumber, pdfDocument.numPages)
        );

        currentPage = pageNumber;

        const page = await pdfDocument.getPage(currentPage);

        const viewport = page.getViewport({
            scale: zoom,
            rotation
        });

        currentViewport = viewport;

        pdfCanvas.width = Math.ceil(viewport.width);
        pdfCanvas.height = Math.ceil(viewport.height);

        overlay.width = pdfCanvas.width;
        overlay.height = pdfCanvas.height;

        pdfPage.style.width = `${viewport.width}px`;
        pdfPage.style.height = `${viewport.height}px`;

        await page.render({
            canvasContext: ctx,
            viewport
        }).promise;

        if (pageNumberInput) {
            pageNumberInput.value = currentPage;
            pageNumberInput.max = pdfDocument.numPages;
        }

        renderOverlay();
        highlightActiveThumbnail();

        setStatus(`Page ${currentPage} of ${pdfDocument.numPages}`);
    }

    // ==================================================
    // THUMBNAILS
    // ==================================================

    async function renderThumbnails() {
        if (!pdfDocument) return;

        thumbnails.innerHTML = "";

        for (
            let pageNumber = 1;
            pageNumber <= pdfDocument.numPages;
            pageNumber++
        ) {
            const page = await pdfDocument.getPage(pageNumber);

            const viewport = page.getViewport({
                scale: 0.2
            });

            const canvas = document.createElement("canvas");
            const thumbnailContext = canvas.getContext("2d");

            canvas.width = viewport.width;
            canvas.height = viewport.height;

            await page.render({
                canvasContext: thumbnailContext,
                viewport
            }).promise;

            const button = document.createElement("button");

            button.className = "page-thumbnail";
            button.type = "button";
            button.dataset.page = pageNumber;

            const label = document.createElement("span");
            label.textContent = `Page ${pageNumber}`;

            button.appendChild(canvas);
            button.appendChild(label);

            button.addEventListener("click", () => {
                rotation = 0;
                renderPage(pageNumber);
            });

            thumbnails.appendChild(button);
        }

        highlightActiveThumbnail();
    }

    function highlightActiveThumbnail() {
        document.querySelectorAll(".page-thumbnail").forEach(button => {
            button.classList.toggle(
                "active",
                Number(button.dataset.page) === currentPage
            );
        });
    }

    // ==================================================
    // COORDINATES
    // ==================================================

    function getPageCoordinates(event) {
        const bounds = overlay.getBoundingClientRect();

        return {
            x: (event.clientX - bounds.left) *
                (overlay.width / bounds.width),

            y: (event.clientY - bounds.top) *
                (overlay.height / bounds.height)
        };
    }

    function canvasToPdfPoint(x, y, viewport = currentViewport) {
        if (!viewport) {
            throw new Error("PDF page is not ready.");
        }

        const point = viewport.convertToPdfPoint(x, y);

        return {
            x: point[0],
            y: point[1]
        };
    }

    function canvasRectangleToPdf(x, y, width, height, viewport) {
        const first = canvasToPdfPoint(x, y, viewport);
        const second = canvasToPdfPoint(
            x + width,
            y + height,
            viewport
        );

        return {
            x: Math.min(first.x, second.x),
            y: Math.min(first.y, second.y),
            width: Math.abs(second.x - first.x),
            height: Math.abs(second.y - first.y)
        };
    }

    // ==================================================
    // OVERLAY PREVIEW
    // ==================================================

    function renderOverlay() {
        overlayCtx.clearRect(
            0,
            0,
            overlay.width,
            overlay.height
        );

        pendingOperations
            .filter(item => item.page === currentPage)
            .forEach(item => {
                const { x, y } = item;

                if (item.type === "text" || item.type === "signature") {
                    overlayCtx.fillStyle =
                        item.type === "signature"
                            ? "#172554"
                            : "#111827";

                    overlayCtx.font = `${item.fontSize || 14}px Arial`;
                    overlayCtx.fillText(item.text, x, y);

                } else if (item.type === "comment") {
                    overlayCtx.fillStyle = "#fef3c7";
                    overlayCtx.fillRect(x, y, 190, 45);

                    overlayCtx.strokeStyle = "#d97706";
                    overlayCtx.strokeRect(x, y, 190, 45);

                    overlayCtx.fillStyle = "#78350f";
                    overlayCtx.font = "12px Arial";

                    overlayCtx.fillText(
                        item.text.substring(0, 28),
                        x + 6,
                        y + 23
                    );

                } else if (item.type === "highlight") {
                    overlayCtx.fillStyle = "rgba(250, 204, 21, 0.4)";
                    overlayCtx.fillRect(
                        x,
                        y,
                        item.width,
                        item.height
                    );

                } else if (item.type === "rectangle") {
                    overlayCtx.strokeStyle = "#2563eb";
                    overlayCtx.lineWidth = 2;

                    overlayCtx.strokeRect(
                        x,
                        y,
                        item.width,
                        item.height
                    );

                } else if (
                    item.type === "image" &&
                    item.previewImage
                ) {
                    overlayCtx.drawImage(
                        item.previewImage,
                        x,
                        y,
                        item.width,
                        item.height
                    );
                }
            });
    }

    // ==================================================
    // PLACE ANNOTATIONS AND IMAGES
    // ==================================================

    overlay.addEventListener("click", event => {
        if (
            !pdfDocument ||
            !currentViewport ||
            selectedTool === "select"
        ) {
            return;
        }

        const position = getPageCoordinates(event);

        const text = toolText
            ? toolText.value.trim()
            : "";

        const fontSize = fontSizeInput
            ? Number(fontSizeInput.value) || 14
            : 14;

        if (
            ["text", "comment", "signature"].includes(selectedTool) &&
            !text
        ) {
            setStatus("Enter text in the Properties panel first.");
            return;
        }

        if (selectedTool === "image" && !uploadedImage) {
            setStatus("Choose an image first.");
            return;
        }

        const operation = {
            type: selectedTool,
            page: currentPage,
            x: position.x,
            y: position.y,
            fontSize,
            text,
            viewport: currentViewport
        };

        if (selectedTool === "highlight") {
            operation.width = 130;
            operation.height = 24;
        }

        if (selectedTool === "rectangle") {
            operation.width = 130;
            operation.height = 70;
        }

        if (selectedTool === "image") {
            operation.width = 150;
            operation.height = 100;
            operation.imageFile = uploadedImage.file;
            operation.previewImage = uploadedImage.preview;
        }

        pendingOperations.push(operation);

        renderOverlay();

        setStatus(
            `${selectedTool} placed on page ${currentPage}. Save to apply it.`
        );
    });

    // ==================================================
    // PAGE NAVIGATION
    // ==================================================

    if (pageNumberInput) {
        pageNumberInput.addEventListener("change", event => {
            const page = Number(event.target.value);

            if (Number.isInteger(page)) {
                rotation = 0;
                renderPage(page);
            }
        });
    }

    if (previousPageButton) {
        previousPageButton.addEventListener("click", () => {
            rotation = 0;
            renderPage(currentPage - 1);
        });
    }

    if (nextPageButton) {
        nextPageButton.addEventListener("click", () => {
            rotation = 0;
            renderPage(currentPage + 1);
        });
    }

    // ==================================================
    // ZOOM AND ROTATION
    // ==================================================

    if (zoomLevel) {
        zoomLevel.addEventListener("change", event => {
            zoom = Number(event.target.value) || 1;
            renderPage(currentPage);
        });
    }

    if (rotatePageButton) {
        rotatePageButton.addEventListener("click", () => {
            rotation = (rotation + 90) % 360;
            renderPage(currentPage);

            setStatus(
                "Page rotated in viewer. Rotation is not saved yet."
            );
        });
    }

    // ==================================================
    // REFRESH PDF AFTER PAGE OPERATION
    // ==================================================

    async function refreshPdf(pageToShow = 1) {
        if (loadingTask) {
            try {
                await loadingTask.destroy();
            } catch (error) {
                console.warn("PDF cleanup warning:", error);
            }
        }

        pdfDocument = null;
        loadingTask = null;
        currentViewport = null;
        pendingOperations = [];

        const freshUrl =
            `${pdfUrl}${pdfUrl.includes("?") ? "&" : "?"}_=${Date.now()}`;

        await openPdf(freshUrl);

        if (pageNumberInput) {
            pageNumberInput.max = pdfDocument.numPages;
        }

        await renderThumbnails();

        const targetPage = Math.max(
            1,
            Math.min(pageToShow, pdfDocument.numPages)
        );

        await renderPage(targetPage);
    }

    // ==================================================
    // BACKEND PAGE OPERATIONS
    // ==================================================

    async function performPageOperation(
        operation,
        argumentsData,
        targetPage
    ) {
        try {
            if (!pdfDocument) {
                throw new Error("PDF is not loaded.");
            }

            if (pendingOperations.length > 0) {
                const confirmSave = window.confirm(
                    "You have unsaved annotations. Continue and discard them?"
                );

                if (!confirmSave) return;
            }

            if (addPageButton) addPageButton.disabled = true;
            if (deletePageButton) deletePageButton.disabled = true;
            if (insertPageButton) insertPageButton.disabled = true;

            setStatus(`${operation} in progress...`);

            const data = await apiRequest(
                `/documents/${documentId}/pdf-editor/${operation}`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(argumentsData)
                }
            );

            await refreshPdf(targetPage);

            setStatus(
                `${data.message || "PDF updated successfully."} Version: ${data.version}`
            );

        } catch (error) {
            console.error(error);
            setStatus(`${operation} failed: ${error.message}`);

        } finally {
            if (addPageButton) addPageButton.disabled = false;
            if (deletePageButton) deletePageButton.disabled = false;
            if (insertPageButton) insertPageButton.disabled = false;
        }
    }

    if (addPageButton) {
        addPageButton.addEventListener("click", () => {
            if (!pdfDocument) return;

            performPageOperation(
                "add_page",
                {
                    position: null,
                    width: 595,
                    height: 842
                },
                pdfDocument.numPages + 1
            );
        });
    }

    if (insertPageButton) {
        insertPageButton.addEventListener("click", () => {
            if (!pdfDocument) return;

            performPageOperation(
                "add_page",
                {
                    position: currentPage,
                    width: 595,
                    height: 842
                },
                currentPage
            );
        });
    }

    if (deletePageButton) {
        deletePageButton.addEventListener("click", () => {
            if (!pdfDocument) return;

            if (pdfDocument.numPages <= 1) {
                setStatus("Cannot delete the only page in a PDF.");
                return;
            }

            const confirmed = window.confirm(
                `Are you sure you want to delete page ${currentPage}?`
            );

            if (!confirmed) return;

            const targetPage = Math.min(
                currentPage,
                pdfDocument.numPages - 1
            );

            performPageOperation(
                "delete_page",
                {
                    page_number: currentPage
                },
                targetPage
            );
        });
    }

    // ==================================================
    // IMAGE SELECTION
    // ==================================================

    if (imageInput) {
        imageInput.addEventListener("change", event => {
            const file = event.target.files[0];

            if (!file) return;

            if (
                !["image/png", "image/jpeg"].includes(file.type)
            ) {
                setStatus("Only PNG and JPEG images are supported.");
                event.target.value = "";
                return;
            }

            if (file.size > 5 * 1024 * 1024) {
                setStatus("Image size must not exceed 5 MB.");
                event.target.value = "";
                return;
            }

            const reader = new FileReader();

            reader.onload = () => {
                const preview = new Image();

                preview.onload = () => {
                    uploadedImage = {
                        file,
                        preview
                    };

                    setTool("image");

                    setStatus(
                        "Image selected. Click on the PDF page to position it."
                    );
                };

                preview.onerror = () => {
                    setStatus("Could not preview the selected image.");
                };

                preview.src = reader.result;
            };

            reader.onerror = () => {
                setStatus("Could not read the selected image.");
            };

            reader.readAsDataURL(file);
        });
    }

    // ==================================================
    // UPLOAD IMAGE
    // ==================================================

    async function uploadImage(file) {
        const formData = new FormData();

        formData.append("file", file, file.name);

        const data = await apiRequest(
            `/documents/${documentId}/pdf-editor/upload-image`,
            {
                method: "POST",
                body: formData
            }
        );

        if (!data.image_name) {
            throw new Error(
                "Backend did not return the uploaded image filename."
            );
        }

        return data.image_name;
    }

    // ==================================================
    // SAVE IMAGE OPERATION
    // ==================================================

    async function saveImageOperation(operation) {
        if (!operation.imageFile) {
            throw new Error("No image file selected.");
        }

        if (!operation.viewport) {
            throw new Error("Image position information is missing.");
        }

        setStatus("Uploading image...");

        const imageName = await uploadImage(operation.imageFile);

        setStatus("Inserting image into PDF...");

        const rectangle = canvasRectangleToPdf(
            operation.x,
            operation.y,
            operation.width,
            operation.height,
            operation.viewport
        );

        const data = await apiRequest(
            `/documents/${documentId}/pdf-editor/insert_image`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    page_number: operation.page,
                    image_name: imageName,
                    x: rectangle.x,
                    y: rectangle.y,
                    width: rectangle.width,
                    height: rectangle.height
                })
            }
        );

        return data;
    }

    // ==================================================
    // PREPARE ANNOTATION DATA
    // ==================================================

    function prepareBackendOperation(operation) {
        const pdfPoint = canvasToPdfPoint(
            operation.x,
            operation.y,
            operation.viewport
        );

        const result = {
            type: operation.type,
            page: operation.page,
            x: pdfPoint.x,
            y: pdfPoint.y
        };

        if (
            operation.type === "text" ||
            operation.type === "comment" ||
            operation.type === "signature"
        ) {
            result.text = operation.text;
        }

        if (operation.type === "text") {
            result.fontSize = operation.fontSize;
        }

        if (
            operation.type === "highlight" ||
            operation.type === "rectangle"
        ) {
            const rectangle = canvasRectangleToPdf(
                operation.x,
                operation.y,
                operation.width,
                operation.height,
                operation.viewport
            );

            result.x = rectangle.x;
            result.y = rectangle.y;
            result.width = rectangle.width;
            result.height = rectangle.height;
        }

        return result;
    }

    // ==================================================
    // SAVE PDF
    // ==================================================

    if (savePdfButton) {
        savePdfButton.addEventListener("click", savePdf);
    }

    async function savePdf() {
        if (pendingOperations.length === 0) {
            setStatus("No pending changes to save.");
            return;
        }

        if (savePdfButton) {
            savePdfButton.disabled = true;
        }

        const operationsToSave = [...pendingOperations];

        try {
            const batchOperations = operationsToSave
                .filter(item => item.type !== "image")
                .map(prepareBackendOperation);

            const imageOperations = operationsToSave.filter(
                item => item.type === "image"
            );

            let latestVersion = null;

            if (batchOperations.length > 0) {
                setStatus("Saving annotations...");

                const data = await apiRequest(
                    `/documents/${documentId}/pdf-editor/save`,
                    {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            operations: batchOperations
                        })
                    }
                );

                latestVersion = data.version;
            }

            for (let index = 0; index < imageOperations.length; index++) {
                setStatus(
                    `Saving image ${index + 1} of ${imageOperations.length}...`
                );

                const data = await saveImageOperation(
                    imageOperations[index]
                );

                latestVersion = data.version;
            }

            pendingOperations = [];
            renderOverlay();

            setStatus(
                `Saved successfully. Latest version: ${latestVersion}`
            );

            setTimeout(() => {
                window.location.href = `/documents/${documentId}`;
            }, 1200);

        } catch (error) {
            console.error("PDF save error:", error);
            setStatus(`Save failed: ${error.message}`);

        } finally {
            if (savePdfButton) {
                savePdfButton.disabled = false;
            }
        }
    }

    // ==================================================
    // START EDITOR
    // ==================================================

    loadPdf();

})();
