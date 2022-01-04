// Built-in deps
// External uses
use futures::{channel::mpsc, executor::block_on, SinkExt};
// Local uses

/// If its placed inside thread::spawn closure it will notify channel when this thread panics.
/// 如果它被放置在 thread::spawn 闭包中，它会在该线程恐慌时通知 channel。
pub struct ThreadPanicNotify(pub mpsc::Sender<bool>);

impl Drop for ThreadPanicNotify {
    fn drop(&mut self) {
        if std::thread::panicking() {//线程恐慌时，发送通知
            block_on(self.0.send(true)).unwrap();
        }
    }
}
