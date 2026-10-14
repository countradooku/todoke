//! System notifications, while the window is in the background or closed:
//! an offer waiting, a transfer finished.
//!
//! A notification carries no file name (lock screens show them) and has no
//! buttons: an offer is decided in the window, where the receive sheet
//! shows what it holds. Activating one brings the window back.

use gpui_kit::SystemNotification;
use todoke_core::api::OfferInfo;

use crate::format::{self, Summary};

/// The tag of the notification of offer `transfer`.
pub fn offer_tag(transfer: &str) -> String {
    format!("offer-{transfer}")
}

/// An offer awaits a decision.
pub fn offer(offer: &OfferInfo) -> SystemNotification {
    SystemNotification {
        tag: offer_tag(&offer.transfer).into(),
        title: format!("{} wants to send you files", format::device(&offer.from)).into(),
        body: format!(
            "{}. Open todoke to see them and decide.",
            Summary::of(&offer.entries).counts()
        )
        .into(),
        actions: Vec::new(),
    }
}

/// A transfer ended; `text` is the notice the window shows for it.
pub fn finished(transfer: &str, text: &str) -> SystemNotification {
    SystemNotification {
        tag: format!("transfer-{transfer}").into(),
        title: "todoke".into(),
        body: text.to_owned().into(),
        actions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::fixtures::offer as an_offer;

    #[test]
    fn an_offer_notification_names_no_file() {
        let shown = offer(&an_offer(
            "t1",
            &[("secret-plan.pdf", "application/pdf", 2048)],
        ));
        assert_eq!(shown.tag.as_ref(), "offer-t1");
        assert!(!shown.title.contains("secret"));
        assert!(!shown.body.contains("secret"), "{}", shown.body);
        assert_eq!(shown.actions, []);
    }
}
