export function registerRulesActions(registry, ctx) {
  registry.register("rules-columns-toggle", async ({ target }) => {
    ctx.toggleMenu("rules-columns-menu", "rules-columns-toggle");
  });

  registry.register("rules-filters-toggle", async () => {
    ctx.state.rules.filtersOpen = !ctx.state.rules.filtersOpen;
    ctx.renderRulesFiltersRevealer();
  });

  registry.register("rules-open-lab", async () => {
    ctx.clearRuleLabEditingContext();
    localStorage.setItem("spuc-web-last-route", "rulelab");
    ctx.setRoute("rulelab");
  });

  registry.register("rules-import-stix", async () => {
    const input = document.getElementById("rules-import-file-shortcut");
    if (input instanceof HTMLInputElement) {
      input.click();
    }
  });

  registry.register("rules-bulk-toggle", async () => {
    if (ctx.state.rules.selected.size === 0) return;
    ctx.state.rules.bulkEditOpen = !ctx.state.rules.bulkEditOpen;
    ctx.updateRulesBulkState();
  });

  registry.register("rules-bulk-cancel", async () => {
    ctx.cancelBulkRulesEdit();
  });

  registry.register("rules-export-selected", async () => {
    await ctx.exportSelectedRules("csv");
  });

  registry.register("rules-export-selected-csv", async () => {
    await ctx.exportSelectedRules("csv");
  });

  registry.register("rules-export-selected-stix", async () => {
    await ctx.exportSelectedRules("stix-bundle");
  });

  registry.register("rules-duplicate-selected", async () => {
    await ctx.duplicateSelectedRules();
  });

  registry.register("rules-export-selected-download", async () => {
    if (!ctx.state.rules.lastExportSelectedCsv) return;
    const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
    ctx.downloadTextFile(ctx.state.rules.lastExportSelectedCsv, `spuc-rules-selected-${ts}.csv`, "text/csv;charset=utf-8");
    ctx.showToast("toast.export_ready");
  });

  registry.register("rules-sort-column", async ({ target }) => {
    ctx.toggleRulesSortColumn(target.dataset.column);
  });

  registry.register("rules-view-mode", async ({ target }) => {
    ctx.setRulesViewMode(target.dataset.mode || "table");
  });

  registry.register("rules-type-toggle", async ({ target }) => {
    const type = target.dataset.type;
    if (!type) return;
    if (ctx.state.rules.typeFilters.has(type)) {
      ctx.state.rules.typeFilters.delete(type);
    } else {
      ctx.state.rules.typeFilters.add(type);
    }
    target.classList.toggle("active", ctx.state.rules.typeFilters.has(type));
    ctx.scheduleRulesReload();
  });

  registry.register("rules-select-all-toggle", async () => {
    const filtered = ctx.applyRulesClientFilters(ctx.state.rules.allEntries);
    const shouldSelect = !filtered.length || filtered.some((entry) => !ctx.state.rules.selected.has(entry.id));
    filtered.forEach((entry) => {
      if (shouldSelect) ctx.state.rules.selected.add(entry.id);
      else ctx.state.rules.selected.delete(entry.id);
    });
    ctx.renderRulesTable();
  });

  registry.register("rules-page", async ({ target }) => {
    await ctx.loadRules(Number(target.dataset.page || "1"));
  });
}
