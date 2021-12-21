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

#include "plugins.h"

std::string plugins_load_from_config(
    falco_configuration& config,
    falco_engine* engine,
    sinsp *inspector,
    std::list<std::shared_ptr<sinsp_plugin>>& loaded_plugins,
    filter_check_list& filter_checks)
{
#ifdef MUSL_OPTIMIZED_BUILD
    throw std::invalid_argument(string("Can not load/use plugins with musl optimized build"));
#else
    // An input plugin can either be a source or a capture plugin.
    // Events will be generated from this plugin.
    std::shared_ptr<sinsp_plugin> input_plugin = NULL;

    // The loaded event source.
    std::string event_source;

    // Factories that can create filters/formatters for
	// the (single) source supported by the (single) input plugin.
	std::shared_ptr<gen_event_filter_factory> plugin_filter_factory(new sinsp_filter_factory(inspector, filter_checks));
	std::shared_ptr<gen_event_formatter_factory> plugin_formatter_factory(new sinsp_evt_formatter_factory(inspector, filter_checks));

    // Set json formatting
    if(config.m_json_output)
    {
        plugin_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
    }

    // Read the configuration and load the plugins
    for(auto &p : config.m_plugins)
    {
        falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");
        std::shared_ptr<sinsp_plugin> plugin = sinsp_plugin::register_plugin(inspector,
            p.m_library_path,
            (p.m_init_config.empty() ? NULL : (char *)p.m_init_config.c_str()),
            filter_checks);

        if (plugin->type() == TYPE_SOURCE_PLUGIN)
        {
            sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());
            if (event_source.size() > 0)
            {
                throw std::invalid_argument(string("Can not load multiple source plugins. Source ") + event_source + " already loaded");
            }

            if(input_plugin != NULL)
            {
                if (input_plugin->type() == TYPE_SOURCE_PLUGIN)
                {
                    throw std::invalid_argument(string("Can not load multiple plugins as input. ") + input_plugin->name() + " already loaded");
                }
            }
            else
            {
                input_plugin = plugin;
                inspector->set_input_plugin(p.m_name);
                if(!p.m_open_params.empty())
                {
                    inspector->set_input_plugin_open_params(p.m_open_params.c_str());
                }
            }
            event_source = splugin->event_source();
            engine->add_source(event_source, plugin_filter_factory, plugin_formatter_factory);
        }
        else if (plugin->type() == TYPE_CAPTURE_PLUGIN)
        {
            if(input_plugin != NULL)
            {
                throw std::invalid_argument(string("Can not load multiple plugins as input. ") + input_plugin->name() + " already loaded");
            }

            input_plugin = plugin;
            inspector->set_input_plugin(p.m_name);
            if(!p.m_open_params.empty())
            {
                inspector->set_input_plugin_open_params(p.m_open_params.c_str());
            }
        }

        loaded_plugins.push_back(plugin);
    }
    
    if (event_source.size() == 0)
    {
        return event_source;
    }

    // If the extractor plugin names compatible sources,
    // ensure that the input plugin's source is in the list
    // of compatible sources.
    std::set<std::string> compat_sources_seen;
    for(auto plugin : loaded_plugins)
    {
        if (plugin->type() == TYPE_EXTRACTOR_PLUGIN)
        {
            sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(plugin.get());
            const std::set<std::string> &compat_sources = eplugin->extract_event_sources();
            if(!compat_sources.empty())
            {
                if (compat_sources.find(event_source) == compat_sources.end())
                {
                    throw std::invalid_argument(string("Extractor plugin not compatible with event source ") + event_source);
                }

                for(const auto &compat_source : compat_sources)
                {
                    if(compat_sources_seen.find(compat_source) != compat_sources_seen.end())
                    {
                        throw std::invalid_argument(string("Extractor plugins have overlapping compatible event source ") + compat_source);
                    }
                    compat_sources_seen.insert(compat_source);
                }
            }
        }
    }

    return event_source;
#endif // MUSL_OPTIMIZED_BUILD
}

void plugins_check_engine_compatibility(falco_engine *engine, sinsp *inspector)
{
    std::list<sinsp_plugin::info> infos = sinsp_plugin::plugin_infos(inspector);
    for(auto &info : infos)
    {
        std::string required_version;

        if(!engine->is_plugin_compatible(info.name, info.plugin_version.as_string(), required_version))
        {
            throw std::invalid_argument(std::string("Plugin ") + info.name + " version " + info.plugin_version.as_string() + " not compatible with required plugin version " + required_version);
        }
    }
}

void plugins_print_list(sinsp *inspector)
{
    std::ostringstream os;
    std::list<sinsp_plugin::info> infos = sinsp_plugin::plugin_infos(inspector);
    for(auto &info : infos)
    {
        os << "Name: " << info.name << std::endl;
        os << "Description: " << info.description << std::endl;
        os << "Contact: " << info.contact << std::endl;
        os << "Version: " << info.plugin_version.as_string() << std::endl;

        std::string type;
        switch (info.type)
        {
            case TYPE_SOURCE_PLUGIN:
                type = "source";
                break;
            case TYPE_EXTRACTOR_PLUGIN:
                type = "extractor";
                break;
            case TYPE_CAPTURE_PLUGIN:
                type = "capture";
                break;
            default:
                ASSERT(false);
        }
        os << "Type: " + type + " plugin" << std::endl;

        if(info.type == TYPE_SOURCE_PLUGIN)
        {
            os << "ID: " << info.id << std::endl;
        }
    }

    printf("%lu Plugins Loaded:\n\n%s\n", infos.size(), os.str().c_str());
}