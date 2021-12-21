/*
Copyright (C) 2020 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <sinsp.h>
#include <falco_engine.h>
#include "configuration.h"

std::string plugins_load_from_config(
    falco_configuration& config,
    falco_engine* engine,
    sinsp *inspector,
    std::list<std::shared_ptr<sinsp_plugin>>& loaded_plugins,
    filter_check_list& filter_checks);

void plugins_check_engine_compatibility(falco_engine *engine, sinsp *inspector);

void plugins_print_list(sinsp *inspector);