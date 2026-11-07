document.addEventListener("DOMContentLoaded", () => {

  // Mobile sidebar
  const toggle = document.getElementById("menuToggle");
  const sidebar = document.getElementById("sidebar");

  if (toggle && sidebar) {
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  // Selected file display
  const fileInput = document.getElementById("fileInput");
  const selectedFile = document.getElementById("selectedFile");

  if (fileInput && selectedFile) {
    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];

      selectedFile.textContent = file
        ? `${file.name} (${(file.size / 1048576).toFixed(2)} MB)`
        : "No file selected";
    });
  }

  // Upload validation
  const uploadForm = document.getElementById("uploadForm");

  if (uploadForm) {
    uploadForm.addEventListener("submit", (event) => {

      const file = fileInput.files[0];
      const message = document.getElementById("uploadMessage");

      const allowed = [".pdf", ".doc", ".docx", ".txt", ".csv"];

      const extension = file
        ? "." + file.name.split(".").pop().toLowerCase()
        : "";

      if (!file) {
        event.preventDefault();
        message.textContent = "Choose a file first.";
      }
      else if (!allowed.includes(extension)) {
        event.preventDefault();
        message.textContent = "This file type is not allowed.";
      }
      else if (file.size > 10 * 1024 * 1024) {
        event.preventDefault();
        message.textContent = "The file exceeds the 10 MB limit.";
      }
    });
  }

  // Table search
  function searchTable(inputId, tableId) {

    const input = document.getElementById(inputId);
    const table = document.getElementById(tableId);

    if (!input || !table) return;

    input.addEventListener("input", () => {

      const query = input.value.toLowerCase();

      table.querySelectorAll("tbody tr").forEach(row => {
        row.hidden = !row.innerText.toLowerCase().includes(query);
      });

    });
  }

  searchTable("documentSearch", "documentsTable");
  searchTable("auditSearch", "auditTable");

});