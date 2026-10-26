use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DomainClassification {
    pub domain: String,
    pub app_name: String,
    pub category: String,
}

pub struct DomainClassifier {
    known_domains: HashMap<&'static str, (&'static str, &'static str)>,
}

impl DomainClassifier {
    pub fn new() -> Self {
        let mut map = HashMap::new();

        // Work & Productivity
        map.insert("chatgpt.com", ("ChatGPT AI", "work_productivity"));
        map.insert("openai.com", ("OpenAI", "work_productivity"));
        map.insert("claude.ai", ("Claude AI", "work_productivity"));
        map.insert("anthropic.com", ("Anthropic", "work_productivity"));
        map.insert("github.com", ("GitHub", "work_productivity"));
        map.insert("gitlab.com", ("GitLab", "work_productivity"));
        map.insert("atlassian.net", ("Atlassian Jira/Confluence", "work_productivity"));
        map.insert("jira.com", ("Jira", "work_productivity"));
        map.insert("trello.com", ("Trello", "work_productivity"));
        map.insert("notion.so", ("Notion", "work_productivity"));
        map.insert("slack.com", ("Slack", "work_productivity"));
        map.insert("microsoft.com", ("Microsoft 365", "work_productivity"));
        map.insert("office.com", ("Office Online", "work_productivity"));
        map.insert("teams.microsoft.com", ("Microsoft Teams", "work_productivity"));
        map.insert("docs.google.com", ("Google Docs", "work_productivity"));
        map.insert("drive.google.com", ("Google Drive", "work_productivity"));
        map.insert("mail.google.com", ("Gmail", "work_productivity"));
        map.insert("pmgcloud.my.id", ("Internal ERP / ITMS", "work_productivity"));

        // Social Media
        map.insert("facebook.com", ("Facebook", "social"));
        map.insert("fbcdn.net", ("Facebook CDN", "social"));
        map.insert("instagram.com", ("Instagram", "social"));
        map.insert("twitter.com", ("Twitter / X", "social"));
        map.insert("x.com", ("X", "social"));
        map.insert("tiktok.com", ("TikTok", "social"));
        map.insert("linkedin.com", ("LinkedIn", "social"));
        map.insert("reddit.com", ("Reddit", "social"));
        map.insert("threads.net", ("Threads", "social"));

        // Entertainment & Streaming
        map.insert("youtube.com", ("YouTube", "entertainment"));
        map.insert("googlevideo.com", ("YouTube Video CDN", "entertainment"));
        map.insert("youtu.be", ("YouTube Short", "entertainment"));
        map.insert("netflix.com", ("Netflix", "entertainment"));
        map.insert("spotify.com", ("Spotify", "entertainment"));
        map.insert("twitch.tv", ("Twitch", "entertainment"));
        map.insert("disneyplus.com", ("Disney+", "entertainment"));

        // Communication
        map.insert("web.whatsapp.com", ("WhatsApp Web", "communication"));
        map.insert("whatsapp.com", ("WhatsApp", "communication"));
        map.insert("web.telegram.org", ("Telegram Web", "communication"));
        map.insert("telegram.org", ("Telegram", "communication"));
        map.insert("discord.com", ("Discord", "communication"));
        map.insert("zoom.us", ("Zoom", "communication"));

        Self { known_domains: map }
    }

    /// Klasifikasi berdasarkan nama file binary executable (PID Process Image Name)
    pub fn classify_by_exe(&self, exe_name: &str) -> Option<DomainClassification> {
        let clean = exe_name.trim().to_lowercase();
        match clean.as_str() {
            "code.exe" => Some(DomainClassification {
                domain: "code.visualstudio.com".to_string(),
                app_name: "Visual Studio Code".to_string(),
                category: "work_productivity".to_string(),
            }),
            "excel.exe" => Some(DomainClassification {
                domain: "microsoft.com".to_string(),
                app_name: "Microsoft Excel".to_string(),
                category: "work_productivity".to_string(),
            }),
            "winword.exe" => Some(DomainClassification {
                domain: "microsoft.com".to_string(),
                app_name: "Microsoft Word".to_string(),
                category: "work_productivity".to_string(),
            }),
            "powerpnt.exe" => Some(DomainClassification {
                domain: "microsoft.com".to_string(),
                app_name: "Microsoft PowerPoint".to_string(),
                category: "work_productivity".to_string(),
            }),
            "outlook.exe" => Some(DomainClassification {
                domain: "outlook.office.com".to_string(),
                app_name: "Microsoft Outlook".to_string(),
                category: "work_productivity".to_string(),
            }),
            "slack.exe" => Some(DomainClassification {
                domain: "slack.com".to_string(),
                app_name: "Slack".to_string(),
                category: "work_productivity".to_string(),
            }),
            "teams.exe" | "ms-teams.exe" => Some(DomainClassification {
                domain: "teams.microsoft.com".to_string(),
                app_name: "Microsoft Teams".to_string(),
                category: "work_productivity".to_string(),
            }),
            "zoom.exe" => Some(DomainClassification {
                domain: "zoom.us".to_string(),
                app_name: "Zoom Meetings".to_string(),
                category: "communication".to_string(),
            }),
            "discord.exe" => Some(DomainClassification {
                domain: "discord.com".to_string(),
                app_name: "Discord".to_string(),
                category: "communication".to_string(),
            }),
            "spotify.exe" => Some(DomainClassification {
                domain: "spotify.com".to_string(),
                app_name: "Spotify".to_string(),
                category: "entertainment".to_string(),
            }),
            "telegram.exe" => Some(DomainClassification {
                domain: "telegram.org".to_string(),
                app_name: "Telegram Desktop".to_string(),
                category: "communication".to_string(),
            }),
            "whatsapp.exe" => Some(DomainClassification {
                domain: "whatsapp.com".to_string(),
                app_name: "WhatsApp Desktop".to_string(),
                category: "communication".to_string(),
            }),
            "saplogon.exe" => Some(DomainClassification {
                domain: "erp.pmgcloud.my.id".to_string(),
                app_name: "SAP ERP".to_string(),
                category: "work_productivity".to_string(),
            }),
            "postman.exe" => Some(DomainClassification {
                domain: "postman.com".to_string(),
                app_name: "Postman API".to_string(),
                category: "work_productivity".to_string(),
            }),
            "dbeaver.exe" => Some(DomainClassification {
                domain: "dbeaver.io".to_string(),
                app_name: "DBeaver SQL".to_string(),
                category: "work_productivity".to_string(),
            }),
            _ => None,
        }
    }

    /// Apakah executable ini merupakan web browser (yang membutuhkan parsing title tab)
    pub fn is_browser_process(&self, exe_name: &str) -> bool {
        let clean = exe_name.trim().to_lowercase();
        matches!(
            clean.as_str(),
            "chrome.exe"
                | "msedge.exe"
                | "firefox.exe"
                | "brave.exe"
                | "opera.exe"
                | "opera_gx.exe"
                | "vivaldi.exe"
                | "arc.exe"
                | "iexplore.exe"
        )
    }

    /// Normalisasi FQDN (strip trailing dot, lowercase, buang www.)
    pub fn normalize_domain(&self, raw: &str) -> String {
        let mut d = raw.trim().to_lowercase();
        // Hapus trailing dot (DNS query root dot: misal "google.com.")
        if d.ends_with('.') {
            d.pop();
        }
        // Hapus port jika ada
        if let Some(pos) = d.find(':') {
            d.truncate(pos);
        }
        // Hapus prefix www.
        if d.starts_with("www.") {
            d = d[4..].to_string();
        }
        d
    }

    /// Klasifikasi domain menjadi DomainClassification (app_name & category)
    pub fn classify(&self, raw_domain: &str) -> DomainClassification {
        let domain = self.normalize_domain(raw_domain);

        // 1. Cek exact match
        if let Some(&(app, cat)) = self.known_domains.get(domain.as_str()) {
            return DomainClassification {
                domain,
                app_name: app.to_string(),
                category: cat.to_string(),
            };
        }

        // 2. Cek suffix match (misal m.facebook.com -> facebook.com)
        for (&known, &(app, cat)) in &self.known_domains {
            if domain.ends_with(known) {
                // Pastikan batas subdomain tepat (misal bukan 'notfacebook.com')
                let prefix_len = domain.len() - known.len();
                if prefix_len == 0 || domain.as_bytes()[prefix_len - 1] == b'.' {
                    return DomainClassification {
                        domain,
                        app_name: app.to_string(),
                        category: cat.to_string(),
                    };
                }
            }
        }

        // 3. Fallback jika domain tidak terdaftar
        let default_app = capitalize_domain(&domain);
        DomainClassification {
            domain,
            app_name: default_app,
            category: "general".to_string(),
        }
    }
}

fn capitalize_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        let name = parts[parts.len() - 2];
        if !name.is_empty() {
            let mut chars = name.chars();
            return match chars.next() {
                None => domain.to_string(),
                Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
            };
        }
    }
    domain.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_normalization_and_classification() {
        let classifier = DomainClassifier::new();

        let res = classifier.classify("www.chatgpt.com.");
        assert_eq!(res.domain, "chatgpt.com");
        assert_eq!(res.app_name, "ChatGPT AI");
        assert_eq!(res.category, "work_productivity");

        let res2 = classifier.classify("m.facebook.com:443");
        assert_eq!(res2.domain, "m.facebook.com");
        assert_eq!(res2.app_name, "Facebook");
        assert_eq!(res2.category, "social");
    }

    #[test]
    fn test_process_classification() {
        let classifier = DomainClassifier::new();

        assert!(classifier.is_browser_process("chrome.exe"));
        assert!(classifier.is_browser_process("msedge.exe"));
        assert!(!classifier.is_browser_process("code.exe"));

        let code_res = classifier.classify_by_exe("code.exe").unwrap();
        assert_eq!(code_res.app_name, "Visual Studio Code");
        assert_eq!(code_res.category, "work_productivity");

        let excel_res = classifier.classify_by_exe("excel.exe").unwrap();
        assert_eq!(excel_res.app_name, "Microsoft Excel");
    }
}
