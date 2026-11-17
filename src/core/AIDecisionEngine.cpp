void AIDecisionEngine::setModel(std::unique_ptr<IModel> model) {
    if (!model) {
        spdlog::error("setModel: null modell ignorert");
        return;
    }
    std::shared_ptr<IModel> shared(std::move(model));
    std::string name = shared->name();
    {
        std::lock_guard lock(mutex_);
        model_ = std::move(shared);
    }
    spdlog::info("Modell byttet til: {}", name);
}