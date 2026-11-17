void FirewallCore::reloadModel(const std::string& path) {
    if (!ai_ || !cfg_.ai.enabled) {
        spdlog::warn("Kan ikke laste modell på nytt: AI er ikke aktiv");
        return;
    }
    if (!path.empty()) cfg_.ai.modelPath = path;
    try {
        auto newModel = createModel(cfg_.ai, baseDir_);
        ai_->setModel(std::move(newModel));
        spdlog::info("Modell lastet på nytt: {}", cfg_.ai.modelPath);
        // Invalider cache slik at nye flyter vurderes med ny modell
        if (coordinator_) coordinator_->invalidateCache();
    } catch (const std::exception& e) {
        spdlog::error("Feil ved reload av modell: {}", e.what());
    }
}