use reqwest::{Client, Url};

pub struct MatterMostNotifier {
    webhook_url: Url,
    client: Client,
}

impl MatterMostNotifier {
    pub fn new(webhook_url: Url) -> Self {
        Self {
            webhook_url,
            client: Client::new(),
        }
    }

    pub async fn send_notify(&self, username: &str, text: &str) -> anyhow::Result<()> {
        let parameters = serde_json::json!({
            "username": serde_json::to_value(&username)?,
            "text": serde_json::to_value(text)?,
        });//格式化json

        self.client
            .post(self.webhook_url.clone())
            .json(&parameters)
            .send()
            .await?;//发送，如果出错，则返回错误给调用者

        Ok(())
    }
}
