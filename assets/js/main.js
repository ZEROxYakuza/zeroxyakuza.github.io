(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem("theme");
  if (saved) root.dataset.theme = saved;

  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const next = root.dataset.theme === "light" ? "dark" : "light";
      root.dataset.theme = next;
      localStorage.setItem("theme", next);
    });
  }

  const menu = document.querySelector(".mobile-menu");
  const sidebar = document.querySelector(".sidebar");
  if (menu) menu.addEventListener("click", () => sidebar.classList.toggle("open"));
})();
