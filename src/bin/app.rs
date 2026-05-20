use crate::{bye::Bye, logkeys::LogKeys};
use clap::Parser;
use color_eyre::eyre::Result;
use crossterm::event::{self};
use ratatui::{DefaultTerminal, Frame, layout::Rect};
use ratatui_textarea::{Input, Key};

#[async_trait::async_trait]
pub trait Screen {
    async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>>;
    fn render(&mut self, f: &mut Frame);
}

#[async_trait::async_trait]
pub trait Section: Send {
    async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Section>>;
    fn render(&mut self, r: &Rect, f: &mut Frame, focus: bool);
    fn top(&self) -> bool;
    fn title(&self) -> String;
    fn has_popup(&self) -> bool;
}

mod helper {
    use std::error::Error;

    use ed25519_dalek_blake2b::{Keypair, PublicKey, SecretKey};
    use ratatui::{
        Frame,
        layout::{Alignment, Constraint, Layout, Rect},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Clear, Paragraph, Wrap},
    };
    use ratatui_textarea::TextArea;

    pub fn is_empty(field: &str) -> bool {
        field.trim().is_empty()
    }

    pub fn keypair_from_str(
        public_key: &str,
        private_key: &str,
    ) -> Result<Keypair, Box<dyn Error>> {
        match (
            PublicKey::from_bytes(&hex::decode(public_key)?),
            SecretKey::from_bytes(&hex::decode(private_key)?),
        ) {
            (Ok(pk), Ok(sk)) => Ok(Keypair {
                secret: sk,
                public: pk,
            }),
            _ => Err("Invalid keypair.".into()),
        }
    }

    pub fn lines_to_string(lines: &[String]) -> String {
        lines
            .iter()
            .fold(String::new(), |acc, l| [acc, l.clone()].concat())
    }

    pub fn render_popup(f: &mut Frame, text: String) {
        let [_, l, _] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Percentage(60),
            Constraint::Fill(1),
        ])
        .areas(f.area());
        let [_, l, _] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Fill(1),
        ])
        .areas(l);
        let popup = Paragraph::new(text)
            .centered()
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Center)
            .style(Style::default().white())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_set(border::DOUBLE)
                    .title_bottom(" Click enter to close. ".bold())
                    .title_alignment(Alignment::Center)
                    .style(Style::default().fg(ratatui::style::Color::LightYellow)),
            );
        f.render_widget(Clear, l);
        f.render_widget(popup, l);
    }

    pub fn render_private_key_popup<'a>(
        f: &mut Frame,
        rect: &Rect,
        private_key_textarea: &TextArea<'a>,
    ) {
        let [_, l, _] = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Percentage(80),
            Constraint::Fill(1),
        ])
        .areas(*rect);
        let [_, l, _] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(6),
            Constraint::Fill(1),
        ])
        .areas(l);

        f.render_widget(Clear, l);
        f.render_widget(private_key_textarea, l);
    }

    pub fn private_key_block_focus<'a>() -> Block<'a> {
        Block::default()
            .borders(Borders::ALL)
            .border_set(border::DOUBLE)
            .title(" Private Key ".bold())
            .title_alignment(Alignment::Left)
            .style(Style::default().fg(ratatui::style::Color::LightYellow))
    }

    pub fn private_key_block<'a>() -> Block<'a> {
        Block::default()
            .borders(Borders::ALL)
            .title(" Private Key ")
            .title_alignment(Alignment::Left)
    }
}

mod logkeys {

    use crate::{
        Screen,
        dashboard::Dashboard,
        genkeys::GenKeys,
        helper::{is_empty, lines_to_string, render_popup},
    };
    use blocktion::state::service::{
        Account, AccountExistsRequest, node_rpc_service_client::NodeRpcServiceClient,
    };
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Paragraph},
    };
    use ratatui_textarea::{Input, Key, TextArea};
    use tonic::Request;

    #[derive(Clone)]
    pub enum Field {
        PublicKey,
        PrivateKey,
        GenerateKey,
    }

    impl Field {
        pub fn toggle_up(&self) -> Option<Self> {
            match self {
                Self::GenerateKey => Some(Self::PrivateKey),
                Self::PrivateKey => Some(Self::PublicKey),
                Self::PublicKey => None,
            }
        }

        pub fn toggle_down(&self) -> Option<Self> {
            match self {
                Self::GenerateKey => None,
                Self::PrivateKey => Some(Self::GenerateKey),
                Self::PublicKey => Some(Self::PrivateKey),
            }
        }
    }

    pub struct LogKeys<'a> {
        pub public_key_textarea: TextArea<'a>,
        pub private_key_textarea: TextArea<'a>,
        pub field: Field,
        pub node: String,
        pub popup: Option<String>,
    }

    impl LogKeys<'_> {
        pub fn new(node: String) -> Self {
            let mut public_key_textarea = TextArea::default();
            let mut private_key_textarea = TextArea::default();

            public_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );
            public_key_textarea.set_cursor_line_style(Style::default());

            private_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Private Key ")
                    .title_alignment(Alignment::Left),
            );

            private_key_textarea.set_mask_char('\u{2022}');
            private_key_textarea.set_cursor_line_style(Style::default());

            public_key_textarea.set_placeholder_text(" Paste your public key here...");
            private_key_textarea.set_placeholder_text(" Paste your private key here...");

            Self {
                node,
                public_key_textarea,
                private_key_textarea,
                field: Field::PublicKey,
                popup: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for LogKeys<'_> {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Some(_) = self.popup {
                        self.popup = None;
                        return None;
                    }

                    if let Field::GenerateKey = self.field {
                        return Some(Box::new(GenKeys::new(self.node.to_string())));
                    }

                    if is_empty(
                        &self
                            .public_key_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat()),
                    ) {
                        self.public_key_textarea
                            .set_placeholder_text(" A public key is required!");
                        return None;
                    }

                    if is_empty(
                        &self
                            .private_key_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat()),
                    ) {
                        self.private_key_textarea
                            .set_placeholder_text(" A private key is required!");
                        return None;
                    }

                    let public_key = lines_to_string(self.public_key_textarea.lines());

                    match NodeRpcServiceClient::connect(self.node.to_string()).await {
                        Ok(mut conn) => {
                            if let Ok(res) = conn
                                .account_exists(Request::new(AccountExistsRequest {
                                    account: Some(Account {
                                        public_key: public_key.to_string(),
                                    }),
                                }))
                                .await
                            {
                                let res = res.into_inner();
                                if res.exists {
                                    return Some(Box::new(Dashboard::new(&self.node, &public_key)));
                                }
                            }
                        }

                        _ => {
                            self.popup =
                                Some("Couldn't connect to the node. Try another.".to_string());

                            return None;
                        }
                    };

                    self.popup = Some(
                        "The node does not recognize the account. Try again or generate a new keypair.".to_string(),
                    );

                    None
                }

                Input { key: Key::Up, .. } => {
                    if let Some(f) = self.field.toggle_up() {
                        self.field = f;
                    };
                    None
                }

                Input { key: Key::Down, .. } => {
                    if let Some(f) = self.field.toggle_down() {
                        self.field = f;
                    };
                    None
                }

                key => match self.field {
                    Field::PublicKey => {
                        self.public_key_textarea.input(key);
                        None
                    }
                    Field::PrivateKey => {
                        self.private_key_textarea.input(key);
                        None
                    }
                    _ => None,
                },
            }
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom("Use ↑/↓ to move, enter to continue, ^X to quit")
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let [_, centered] = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Percentage(5), Constraint::Percentage(90)])
                .areas(size);

            let logkeys_box = Block::bordered()
                .title(" Log your keys to acess your Blocktion account! ".bold())
                .title_alignment(Alignment::Center);
            f.render_widget(logkeys_box, centered);

            let logkeys_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    Constraint::Min(3),    // title
                    Constraint::Length(3), // pk
                    Constraint::Min(2),
                    Constraint::Length(3), // sk
                    Constraint::Min(2),
                    Constraint::Length(1), // gen k
                    Constraint::Min(3),
                ])
                .split(centered);

            let input_box_layout = Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([
                    Constraint::Min(2),
                    Constraint::Percentage(70),
                    Constraint::Min(2),
                ]);

            let input_chunks_pk = input_box_layout.split(logkeys_chunks[1]);
            let input_chunks_sk = input_box_layout.split(logkeys_chunks[3]);

            let mut new_keys_par = Paragraph::new("No keypair yet? Generate one.").centered();

            self.public_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );
            self.public_key_textarea
                .set_style(Style::default().fg(ratatui::style::Color::White));
            self.public_key_textarea.set_style(Style::default());
            self.public_key_textarea
                .set_placeholder_style(Style::default().dark_gray());

            self.private_key_textarea.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Secret Key ")
                    .title_alignment(Alignment::Left),
            );
            self.private_key_textarea
                .set_style(Style::default().fg(ratatui::style::Color::White));
            self.private_key_textarea.set_style(Style::default());
            self.private_key_textarea
                .set_placeholder_style(Style::default().dark_gray());

            match self.field {
                Field::PrivateKey if matches!(self.popup, None) => {
                    self.private_key_textarea
                        .set_placeholder_style(Style::default().white());
                    self.private_key_textarea
                        .set_style(Style::default().white());
                    self.private_key_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_set(border::DOUBLE)
                            .title(" Secret Key ".bold())
                            .title_alignment(Alignment::Left)
                            .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                    );
                }
                Field::PublicKey if matches!(self.popup, None) => {
                    self.public_key_textarea
                        .set_placeholder_style(Style::default().white());
                    self.public_key_textarea.set_style(Style::default().white());
                    self.public_key_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_set(border::DOUBLE)
                            .title(" Public Key ".bold())
                            .title_alignment(Alignment::Left)
                            .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                    );
                }

                Field::GenerateKey if matches!(self.popup, None) => {
                    new_keys_par =
                        Paragraph::new("No keypair yet? Generate one.".bold().light_yellow())
                            .centered();
                }
                _ => {}
            };

            f.render_widget(&self.public_key_textarea, input_chunks_pk[1]);
            f.render_widget(&self.private_key_textarea, input_chunks_sk[1]);
            f.render_widget(new_keys_par, input_box_layout.split(logkeys_chunks[5])[1]);

            if let Some(p) = self.popup.clone() {
                render_popup(f, p);
            }
        }
    }
}

mod genkeys {
    use std::error::Error;

    use crate::{
        Screen,
        helper::{keypair_from_str, render_popup},
        logkeys::LogKeys,
    };
    use blocktion::{
        blockchain::transaction::{Data, Transaction},
        state::service::node_rpc_service_client::NodeRpcServiceClient,
    };
    use clipboard::{ClipboardContext, ClipboardProvider};
    use ed25519_dalek_blake2b::Keypair;
    use hex::ToHex;
    use rand::rngs::OsRng;
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        symbols::border,
        widgets::{Block, Borders, Paragraph},
    };
    use ratatui_textarea::{Input, Key};
    use tonic::Request;

    const GENERATE_ANOTHER_PAIR: &str = "Not satisfied? Generate another keypair.";

    #[derive(Clone)]
    pub enum Field {
        PublicKey,
        PrivateKey,
        GenerateAnotherKey,
    }

    impl Field {
        pub fn toggle_up(&self) -> Option<Self> {
            match self {
                Self::GenerateAnotherKey => Some(Self::PrivateKey),
                Self::PrivateKey => Some(Self::PublicKey),
                Self::PublicKey => None,
            }
        }

        pub fn toggle_down(&self) -> Option<Self> {
            match self {
                Self::GenerateAnotherKey => None,
                Self::PrivateKey => Some(Self::GenerateAnotherKey),
                Self::PublicKey => Some(Self::PrivateKey),
            }
        }
    }

    #[derive(Clone)]
    pub struct GenKeys {
        pub public_key_content: String,
        pub private_key_content: String,
        pub field: Field,
        pub node: String,
        pub popup: Option<String>,
    }

    impl GenKeys {
        pub fn new(node: String) -> Self {
            let keypair = Keypair::generate(&mut OsRng);

            Self {
                public_key_content: keypair.public.encode_hex(),
                private_key_content: keypair.secret.encode_hex(),
                field: Field::PublicKey,
                node,
                popup: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for GenKeys {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            match input {
                Input {
                    key: Key::Enter, ..
                } => {
                    if let Some(_) = self.popup {
                        self.popup = None;
                        return None;
                    }

                    if let Field::GenerateAnotherKey = self.field {
                        return Some(Box::new(GenKeys::new(self.node.to_string())));
                    }

                    let mut logkeys = LogKeys::new(self.node.to_string());

                    logkeys.private_key_textarea.select_all();
                    logkeys.private_key_textarea.cut();
                    logkeys
                        .private_key_textarea
                        .insert_str(&self.private_key_content);

                    logkeys.public_key_textarea.select_all();
                    logkeys.public_key_textarea.cut();
                    logkeys
                        .public_key_textarea
                        .insert_str(&self.public_key_content);

                    match NodeRpcServiceClient::connect(self.node.to_string()).await {
                        Ok(mut conn) => {
                            let keys = match keypair_from_str(
                                &self.public_key_content,
                                &self.private_key_content,
                            ) {
                                Ok(keys) => keys,
                                Err(_) => {
                                    self.popup =
                                        Some("Failed to validate the keys provided.".to_string());
                                    return None;
                                }
                            };
                            let t = match Transaction::sign(
                                Data::CreateUserAccount {
                                    public_key: keys.public.encode_hex(),
                                },
                                &keys.public.encode_hex::<String>(),
                                0,
                                &keys,
                            ) {
                                Ok(t) => t,
                                Err(_) => {
                                    self.popup = Some(
                                        "Failed to sign the create account transaction."
                                            .to_string(),
                                    );
                                    return None;
                                }
                            }
                            .into();
                            if let Ok(res) = conn.transaction(Request::new(t)).await {
                                let res = res.into_inner();

                                if res.status == 0 {
                                    return Some(Box::new(logkeys));
                                }
                            }
                        }

                        _ => {
                            self.popup =
                                Some("Couldn't connect to the node. Try another.".to_string());
                            return None;
                        }
                    };

                    self.popup = Some(
                        "The blockchain did not accept the create account transaction.".to_string(),
                    );
                    None
                }

                Input { key: Key::Up, .. } => {
                    if let Some(f) = self.field.toggle_up() {
                        self.field = f;
                    }
                    None
                }

                Input { key: Key::Down, .. } => {
                    if let Some(f) = self.field.toggle_down() {
                        self.field = f;
                    }
                    None
                }

                Input {
                    key: Key::Char('c'),
                    ctrl: true,
                    ..
                } => {
                    let ctx: Result<ClipboardContext, Box<dyn Error>> = ClipboardProvider::new();

                    if let Ok(mut ctx) = ctx {
                        let contents = match self.field {
                            Field::PublicKey => self.public_key_content.clone(),
                            Field::PrivateKey => self.private_key_content.clone(),
                            _ => return None,
                        };

                        if let Err(_) = ctx.set_contents(contents) { /*todo*/ }
                    }
                    None
                }

                _ => None,
            }
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom(
                    "Use ↑/↓ to move, ^C to copy key to clipboard, enter to continue, ^X to quit",
                )
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let [_, centered] = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([Constraint::Percentage(5), Constraint::Percentage(90)])
                .areas(size);

            let logkeys_box = Block::bordered()
                .title(" Store the generated keys in a secure place. ".bold())
                .title_alignment(Alignment::Center);
            f.render_widget(logkeys_box, centered);

            let logkeys_chunks = Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    Constraint::Min(3),    // title
                    Constraint::Length(3), // pk
                    Constraint::Min(2),
                    Constraint::Length(3), // sk
                    Constraint::Min(2),
                    Constraint::Length(1), // gen k
                    Constraint::Min(3),
                ])
                .split(centered);

            let input_box_layout = Layout::default()
                .direction(ratatui::layout::Direction::Horizontal)
                .constraints([
                    Constraint::Min(2),
                    Constraint::Percentage(70),
                    Constraint::Min(2),
                ]);
            let mut input_box_pk = Paragraph::new(self.public_key_content.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Public Key ")
                    .title_alignment(Alignment::Left),
            );

            let input_chunks_pk = input_box_layout.split(logkeys_chunks[1]);
            let input_chunks_sk = input_box_layout.split(logkeys_chunks[3]);

            let mut input_box_sk = Paragraph::new(self.private_key_content.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Secret Key ")
                    .title_alignment(Alignment::Left),
            );

            let mut new_keys_par = Paragraph::new(GENERATE_ANOTHER_PAIR).centered();

            match self.field {
                Field::PrivateKey if self.popup == None => {
                    input_box_sk = Paragraph::new(self.private_key_content.as_str())
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Secret Key ".bold())
                                .title_alignment(Alignment::Left)
                                .fg(ratatui::style::Color::LightYellow),
                        )
                        .style(Style::default().fg(ratatui::style::Color::LightYellow));
                }
                Field::PublicKey if self.popup == None => {
                    input_box_pk = Paragraph::new(self.public_key_content.as_str())
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Public Key ".bold())
                                .title_alignment(Alignment::Left)
                                .fg(ratatui::style::Color::LightYellow),
                        )
                        .style(Style::default().fg(ratatui::style::Color::LightYellow));
                }

                Field::GenerateAnotherKey if self.popup == None => {
                    new_keys_par =
                        Paragraph::new(GENERATE_ANOTHER_PAIR.bold().light_yellow()).centered();
                }
                _ => {}
            };

            f.render_widget(input_box_pk, input_chunks_pk[1]);
            f.render_widget(input_box_sk, input_chunks_sk[1]);
            f.render_widget(new_keys_par, input_box_layout.split(logkeys_chunks[5])[1]);

            if let Some(p) = self.popup.clone() {
                render_popup(f, p);
            }
        }
    }
}

mod dashboard {
    use std::collections::HashMap;

    use crate::{
        Screen, Section,
        dashboard::{bid::Bid, options::create_auction::CreateAuction},
    };
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Style, Stylize},
        text::{Line, Span},
        widgets::{Block, List, ListState, Tabs},
    };
    use ratatui_textarea::{Input, Key};

    #[derive(Clone, Hash, Eq, PartialEq)]
    pub enum Page {
        Auctions = 0,
        ProfileHistory = 1,
    }

    impl Page {
        fn all() -> Vec<String> {
            vec!["Auctions".to_string(), "Profile History".to_string()]
        }

        fn next(&self) -> Self {
            match self {
                Self::Auctions | Self::ProfileHistory => Self::ProfileHistory,
            }
        }

        fn previous(&self) -> Self {
            match self {
                Self::Auctions | Self::ProfileHistory => Self::Auctions,
            }
        }
    }

    mod options {
        pub mod create_auction {
            use blake2::{Blake2b, Digest};
            use blocktion::{
                blockchain::{
                    hash,
                    transaction::{Data, Transaction},
                },
                state::service::{
                    Account, AccountExistsRequest, RequestStatus,
                    node_rpc_service_client::NodeRpcServiceClient,
                },
                time,
            };
            use hex::ToHex;
            use ratatui::{
                layout::{Alignment, Constraint, Layout},
                style::{Style, Stylize},
                symbols::border,
                widgets::{Block, Borders},
            };
            use ratatui_textarea::{Input, Key, TextArea};
            use tonic::Request;

            use crate::{
                Section,
                helper::{
                    is_empty, keypair_from_str, lines_to_string, private_key_block,
                    private_key_block_focus, render_popup, render_private_key_popup,
                },
            };

            pub enum Field {
                StartAmount,
                Duration,
                PrivateKey,
            }

            pub struct CreateAuction<'a> {
                pub start_amount_textarea: TextArea<'a>,
                pub duration_textarea: TextArea<'a>,
                pub private_key_textarea: Option<TextArea<'a>>,
                pub field: Field,
                pub node: String,
                pub public_key: String,
                pub popup: Option<String>,
            }

            impl<'a> CreateAuction<'a> {
                pub fn new(node: String, public_key: String) -> Self {
                    let mut start_amount_textarea = TextArea::default();
                    let mut duration_textarea = TextArea::default();

                    start_amount_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Start Amount ")
                            .title_alignment(Alignment::Left),
                    );
                    start_amount_textarea.set_cursor_line_style(Style::default());

                    duration_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Duration ")
                            .title_alignment(Alignment::Left)
                            .title_bottom(" Click ^Z to cancel. "),
                    );
                    duration_textarea.set_cursor_line_style(Style::default());

                    start_amount_textarea.set_placeholder_text(" Insert the amount...");
                    duration_textarea.set_placeholder_text(" Insert the duration in secords...");

                    Self {
                        node,
                        public_key,
                        start_amount_textarea,
                        duration_textarea,
                        private_key_textarea: None,
                        field: Field::StartAmount,
                        popup: None,
                    }
                }

                fn toggle_up(&mut self) {
                    match self.field {
                        Field::StartAmount | Field::Duration => self.field = Field::StartAmount,
                        _ => {}
                    };
                }

                fn toggle_down(&mut self) {
                    match self.field {
                        Field::StartAmount | Field::Duration => self.field = Field::Duration,
                        _ => {}
                    };
                }
            }

            #[async_trait::async_trait]
            impl Section for CreateAuction<'_> {
                fn title(&self) -> String {
                    " Create Auction ".to_string()
                }

                fn top(&self) -> bool {
                    matches!(self.field, Field::StartAmount)
                }

                fn has_popup(&self) -> bool {
                    match &self.popup {
                        Some(_) => true,
                        _ => false,
                    }
                }

                async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Section>> {
                    match input {
                        Input {
                            key: Key::Enter, ..
                        } => {
                            if let Some(_) = self.popup {
                                self.popup = None;
                                return None;
                            }

                            let start_amount_text = self
                                .start_amount_textarea
                                .lines()
                                .iter()
                                .fold(String::new(), |acc, l| [acc, l.clone()].concat());
                            if is_empty(&start_amount_text) {
                                self.start_amount_textarea
                                    .set_placeholder_text(" A start amount is required!");
                                self.start_amount_textarea.cut();
                                self.field = Field::StartAmount;
                                return None;
                            }
                            let start_amount;
                            if let Ok(d) = start_amount_text.parse::<u64>() {
                                start_amount = d;
                            } else {
                                self.start_amount_textarea.set_placeholder_text(
                                    " The start amount should be an integer!",
                                );
                                self.start_amount_textarea.cut();
                                self.field = Field::StartAmount;
                                return None;
                            }

                            let duration_text = self
                                .duration_textarea
                                .lines()
                                .iter()
                                .fold(String::new(), |acc, l| [acc, l.clone()].concat());
                            if is_empty(&duration_text) {
                                self.duration_textarea
                                    .set_placeholder_text(" A duration is required!");
                                self.field = Field::Duration;
                                return None;
                            }
                            let duration;
                            if let Ok(d) = duration_text.parse::<u64>() {
                                duration = d;
                            } else {
                                self.start_amount_textarea.set_placeholder_text(
                                    " The duration should be an integer representing seconds!",
                                );
                                self.field = Field::Duration;
                                return None;
                            }

                            if let Some(private_key_textarea) = self.private_key_textarea.as_mut() {
                                fn exit_popup(
                                    create_auction: &mut CreateAuction,
                                    error: Option<String>,
                                ) {
                                    create_auction.popup = error;
                                    create_auction.field = Field::StartAmount;
                                    create_auction.private_key_textarea = None;
                                }

                                let private_key_text =
                                    lines_to_string(private_key_textarea.lines());

                                if is_empty(&private_key_text) {
                                    private_key_textarea
                                        .set_placeholder_text(" A private key is required!");

                                    exit_popup(&mut self, None);

                                    return None;
                                }

                                match NodeRpcServiceClient::connect(self.node.to_string()).await {
                                    Ok(mut conn) => {
                                        let keys = match keypair_from_str(
                                            &self.public_key,
                                            &private_key_text,
                                        ) {
                                            Ok(keys) => keys,

                                            Err(_) => {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Failed to validate the keys provided."
                                                            .to_string(),
                                                    ),
                                                );

                                                return None;
                                            }
                                        };

                                        let now = match time::now_unix() {
                                            Ok(t) => t,

                                            _ => {
                                                exit_popup(
                                                    &mut self,
                                                    Some("Failed to get time.".to_string()),
                                                );

                                                return None;
                                            }
                                        };

                                        let id = hash::encode_hash(&hash::hash(
                                            Blake2b::new(),
                                            &format!("{}:{}:{}", start_amount, duration, now),
                                        ));

                                        let nonce = match conn
                                            .account_exists(Request::new(AccountExistsRequest {
                                                account: Some(Account {
                                                    public_key: self.public_key.to_string(),
                                                }),
                                            }))
                                            .await
                                        {
                                            Ok(a) => match a.into_inner().nonce {
                                                Some(nonce) => nonce,

                                                None => {
                                                    exit_popup(
                                                        &mut self,
                                                        Some(
                                                            "Failed to get account nonce."
                                                                .to_string(),
                                                        ),
                                                    );

                                                    return None;
                                                }
                                            },

                                            _ => {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Failed to get account nonce.".to_string(),
                                                    ),
                                                );

                                                return None;
                                            }
                                        };

                                        let transaction = match Transaction::sign(
                                        Data::CreateAuction {
                                            auction_id: id,
                                            start_amount,
                                            stop_time: now + duration,
                                        },
                                        &keys.public.encode_hex::<String>(),
                                        nonce,
                                        &keys,
                                    ) {
                                        Ok(t) => t,

                                        Err(_) => {
                                            exit_popup(
                                                &mut self,
                                                Some("Failed to sign the create auction transaction."
                                                    .to_string()),
                                            );

                                            return None;
                                        }
                                    }
                                    .into();

                                        match conn.transaction(Request::new(transaction)).await {
                                            Ok(res) => {
                                                let res = res.into_inner();

                                                if res.status() == RequestStatus::Successful {
                                                    exit_popup(&mut self, Some(
                                                    "Successfully created the auction on-chain."
                                                        .to_string(),
                                                ));
                                                    return None;
                                                } else {
                                                    exit_popup(
                                                        &mut self,
                                                        Some(
                                                            "Failed to create auction on-chain."
                                                                .to_string(),
                                                        ),
                                                    );
                                                    return None;
                                                }
                                            }
                                            Err(_) => {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Couldn't perform the transaction."
                                                            .to_string(),
                                                    ),
                                                );
                                                return None;
                                            }
                                        }
                                    }
                                    _ => {
                                        exit_popup(
                                            &mut self,
                                            Some("Failed to connect to the network.".to_string()),
                                        );
                                        return None;
                                    }
                                }
                            } else {
                                let mut private_key_textarea = TextArea::default();
                                private_key_textarea
                                    .set_placeholder_style(Style::default().white());
                                private_key_textarea.set_style(Style::default().white());
                                private_key_textarea.set_cursor_line_style(Style::default());
                                private_key_textarea.set_mask_char('\u{2022}');
                                private_key_textarea.set_block(private_key_block_focus());
                                private_key_textarea.set_placeholder_text(
                                    " Insert your private key (click ^Z to cancel)...",
                                );

                                self.private_key_textarea = Some(private_key_textarea);
                                self.field = Field::PrivateKey;
                            }
                        }

                        Input {
                            key: Key::Char('z'),
                            ctrl: true,
                            ..
                        } => {
                            self.private_key_textarea = None;
                            self.field = Field::StartAmount;
                        }

                        Input { key: Key::Up, .. } => {
                            if !matches!(self.field, Field::PrivateKey) {
                                self.toggle_up()
                            }
                        }

                        Input { key: Key::Down, .. } => {
                            if !matches!(self.field, Field::PrivateKey) {
                                self.toggle_down()
                            }
                        }

                        Input { .. } => match self.field {
                            Field::Duration => {
                                self.duration_textarea.input(input);
                            }
                            Field::StartAmount => {
                                self.start_amount_textarea.input(input);
                            }
                            Field::PrivateKey => {
                                if let Some(private_key_textarea) =
                                    self.private_key_textarea.as_mut()
                                {
                                    private_key_textarea.input(input);
                                }
                            }
                        },
                    }
                    None
                }

                fn render(
                    &mut self,
                    r: &ratatui::prelude::Rect,
                    f: &mut ratatui::prelude::Frame,
                    focus: bool,
                ) {
                    self.start_amount_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Start Amount ")
                            .title_alignment(Alignment::Left),
                    );
                    self.start_amount_textarea
                        .set_style(Style::default().fg(ratatui::style::Color::White));
                    self.start_amount_textarea.set_style(Style::default());
                    self.start_amount_textarea
                        .set_placeholder_style(Style::default().dark_gray());

                    self.duration_textarea.set_block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Duration ")
                            .title_alignment(Alignment::Left),
                    );
                    self.duration_textarea
                        .set_style(Style::default().fg(ratatui::style::Color::White));
                    self.duration_textarea.set_style(Style::default());
                    self.duration_textarea
                        .set_placeholder_style(Style::default().dark_gray());

                    match self.field {
                        Field::StartAmount
                            if focus && matches!(self.private_key_textarea, None) =>
                        {
                            self.start_amount_textarea
                                .set_placeholder_style(Style::default().white());
                            self.start_amount_textarea
                                .set_style(Style::default().white());
                            self.start_amount_textarea.set_block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_set(border::DOUBLE)
                                    .title(" Start Amount ".bold())
                                    .title_alignment(Alignment::Left)
                                    .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                            );
                        }
                        Field::Duration if focus && matches!(self.private_key_textarea, None) => {
                            self.duration_textarea
                                .set_placeholder_style(Style::default().white());
                            self.duration_textarea.set_style(Style::default().white());
                            self.duration_textarea.set_block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_set(border::DOUBLE)
                                    .title(" Duration ".bold())
                                    .title_alignment(Alignment::Left)
                                    .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                            );
                        }
                        _ => {}
                    };

                    let [_, r, _] = Layout::horizontal([
                        Constraint::Fill(1),
                        Constraint::Percentage(70),
                        Constraint::Fill(1),
                    ])
                    .areas(*r);

                    let [_, lsa, _, ld, _] = Layout::default()
                        .direction(ratatui::layout::Direction::Vertical)
                        .constraints([
                            Constraint::Min(3),
                            Constraint::Length(3),
                            Constraint::Min(2),
                            Constraint::Length(3),
                            Constraint::Min(3),
                        ])
                        .areas(r);

                    f.render_widget(&self.start_amount_textarea, lsa);
                    f.render_widget(&self.duration_textarea, ld);

                    if let Some(p) = self.popup.clone() {
                        render_popup(f, p);
                    }

                    if let Some(p) = self.private_key_textarea.as_mut() {
                        if !focus {
                            p.set_block(private_key_block());
                        } else {
                            p.set_block(private_key_block_focus());
                        }
                        self.popup = None;
                        render_private_key_popup(f, &r, &p);
                    }
                }
            }
        }
    }

    pub mod bid {
        use blocktion::{
            blockchain::transaction::{Data, Transaction},
            state::service::{
                Account, AccountExistsRequest, RequestStatus,
                node_rpc_service_client::NodeRpcServiceClient,
            },
        };
        use hex::ToHex;
        use ratatui::{
            layout::{Alignment, Constraint, Layout},
            style::{Style, Stylize},
            symbols::border,
            widgets::{Block, Borders},
        };
        use ratatui_textarea::{Input, Key, TextArea};
        use tonic::Request;

        use crate::{
            Section,
            helper::{
                is_empty, keypair_from_str, lines_to_string, private_key_block,
                private_key_block_focus, render_popup, render_private_key_popup,
            },
        };

        pub enum Field {
            AuctionId,
            Amount,
            PrivateKey,
        }

        pub struct Bid<'a> {
            pub auction_id_textarea: TextArea<'a>,
            pub amount_textarea: TextArea<'a>,
            pub private_key_textarea: Option<TextArea<'a>>,
            pub field: Field,
            pub node: String,
            pub public_key: String,
            pub popup: Option<String>,
        }

        impl<'a> Bid<'a> {
            pub fn new(node: String, public_key: String) -> Self {
                let mut amount_textarea = TextArea::default();
                let mut auction_id_textarea = TextArea::default();

                amount_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Start Amount ")
                        .title_alignment(Alignment::Left),
                );
                amount_textarea.set_cursor_line_style(Style::default());

                auction_id_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Duration ")
                        .title_alignment(Alignment::Left)
                        .title_bottom(" Click ^Z to cancel. "),
                );
                auction_id_textarea.set_cursor_line_style(Style::default());

                amount_textarea.set_placeholder_text(" Insert the amount...");
                auction_id_textarea.set_placeholder_text(" Insert the auction ID...");

                Self {
                    node,
                    public_key,
                    amount_textarea,
                    auction_id_textarea,
                    private_key_textarea: None,
                    field: Field::AuctionId,
                    popup: None,
                }
            }

            fn toggle_up(&mut self) {
                match self.field {
                    Field::AuctionId | Field::Amount => self.field = Field::AuctionId,
                    _ => {}
                };
            }

            fn toggle_down(&mut self) {
                match self.field {
                    Field::AuctionId | Field::Amount => self.field = Field::Amount,
                    _ => {}
                };
            }
        }

        #[async_trait::async_trait]
        impl Section for Bid<'_> {
            fn title(&self) -> String {
                " Bid ".to_string()
            }

            fn top(&self) -> bool {
                matches!(self.field, Field::AuctionId)
            }

            fn has_popup(&self) -> bool {
                match &self.popup {
                    Some(_) => true,
                    _ => false,
                }
            }

            async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Section>> {
                match input {
                    Input {
                        key: Key::Enter, ..
                    } => {
                        if let Some(_) = self.popup {
                            self.popup = None;
                            return None;
                        }

                        let amount_text = self
                            .amount_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat());
                        if is_empty(&amount_text) {
                            self.amount_textarea
                                .set_placeholder_text(" An amount is required!");
                            self.amount_textarea.cut();
                            self.field = Field::AuctionId;
                            return None;
                        }
                        let amount;
                        if let Ok(d) = amount_text.parse::<u64>() {
                            amount = d;
                        } else {
                            self.amount_textarea
                                .set_placeholder_text(" The amount should be an integer!");
                            self.amount_textarea.cut();
                            self.field = Field::Amount;
                            return None;
                        }

                        let auction_id_text = self
                            .auction_id_textarea
                            .lines()
                            .iter()
                            .fold(String::new(), |acc, l| [acc, l.clone()].concat());
                        if is_empty(&auction_id_text) {
                            self.auction_id_textarea
                                .set_placeholder_text(" An auction ID is required!");
                            self.field = Field::AuctionId;
                            return None;
                        }

                        if let Some(private_key_textarea) = self.private_key_textarea.as_mut() {
                            fn exit_popup(bid: &mut Bid, error: Option<String>) {
                                bid.popup = error;
                                bid.field = Field::AuctionId;
                                bid.private_key_textarea = None;
                            }

                            let private_key_text = lines_to_string(private_key_textarea.lines());

                            if is_empty(&private_key_text) {
                                private_key_textarea
                                    .set_placeholder_text(" A private key is required!");

                                exit_popup(&mut self, None);

                                return None;
                            }

                            match NodeRpcServiceClient::connect(self.node.to_string()).await {
                                Ok(mut conn) => {
                                    let keys =
                                        match keypair_from_str(&self.public_key, &private_key_text)
                                        {
                                            Ok(keys) => keys,

                                            Err(_) => {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Failed to validate the keys provided."
                                                            .to_string(),
                                                    ),
                                                );

                                                return None;
                                            }
                                        };

                                    let nonce = match conn
                                        .account_exists(Request::new(AccountExistsRequest {
                                            account: Some(Account {
                                                public_key: self.public_key.to_string(),
                                            }),
                                        }))
                                        .await
                                    {
                                        Ok(a) => match a.into_inner().nonce {
                                            Some(nonce) => nonce,

                                            None => {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Failed to get account nonce.".to_string(),
                                                    ),
                                                );

                                                return None;
                                            }
                                        },

                                        _ => {
                                            exit_popup(
                                                &mut self,
                                                Some("Failed to get account nonce.".to_string()),
                                            );

                                            return None;
                                        }
                                    };

                                    let transaction = match Transaction::sign(
                                        Data::Bid {
                                            auction_id: auction_id_text.to_string(),
                                            amount,
                                        },
                                        &keys.public.encode_hex::<String>(),
                                        nonce,
                                        &keys,
                                    ) {
                                        Ok(t) => t,

                                        Err(_) => {
                                            exit_popup(
                                                &mut self,
                                                Some(
                                                    "Failed to sign the bid transaction."
                                                        .to_string(),
                                                ),
                                            );

                                            return None;
                                        }
                                    }
                                    .into();

                                    match conn.transaction(Request::new(transaction)).await {
                                        Ok(res) => {
                                            let res = res.into_inner();

                                            if res.status() == RequestStatus::Successful {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Successfully created the bid on-chain."
                                                            .to_string(),
                                                    ),
                                                );
                                                return None;
                                            } else {
                                                exit_popup(
                                                    &mut self,
                                                    Some(
                                                        "Failed to create bid on-chain."
                                                            .to_string(),
                                                    ),
                                                );
                                                return None;
                                            }
                                        }
                                        Err(_) => {
                                            exit_popup(
                                                &mut self,
                                                Some(
                                                    "Couldn't perform the transaction.".to_string(),
                                                ),
                                            );
                                            return None;
                                        }
                                    }
                                }
                                _ => {
                                    exit_popup(
                                        &mut self,
                                        Some("Failed to connect to the network.".to_string()),
                                    );
                                    return None;
                                }
                            }
                        } else {
                            let mut private_key_textarea = TextArea::default();
                            private_key_textarea.set_placeholder_style(Style::default().white());
                            private_key_textarea.set_style(Style::default().white());
                            private_key_textarea.set_cursor_line_style(Style::default());
                            private_key_textarea.set_mask_char('\u{2022}');
                            private_key_textarea.set_block(private_key_block_focus());
                            private_key_textarea.set_placeholder_text(
                                " Insert your private key (click ^Z to cancel)...",
                            );

                            self.private_key_textarea = Some(private_key_textarea);
                            self.field = Field::PrivateKey;
                        }
                    }

                    Input {
                        key: Key::Char('z'),
                        ctrl: true,
                        ..
                    } => {
                        self.private_key_textarea = None;
                        self.field = Field::AuctionId;
                    }

                    Input { key: Key::Up, .. } => {
                        if !matches!(self.field, Field::PrivateKey) {
                            self.toggle_up()
                        }
                    }

                    Input { key: Key::Down, .. } => {
                        if !matches!(self.field, Field::PrivateKey) {
                            self.toggle_down()
                        }
                    }

                    Input { .. } => match self.field {
                        Field::AuctionId => {
                            self.auction_id_textarea.input(input);
                        }
                        Field::Amount => {
                            self.amount_textarea.input(input);
                        }
                        Field::PrivateKey => {
                            if let Some(private_key_textarea) = self.private_key_textarea.as_mut() {
                                private_key_textarea.input(input);
                            }
                        }
                    },
                }
                None
            }

            fn render(
                &mut self,
                r: &ratatui::prelude::Rect,
                f: &mut ratatui::prelude::Frame,
                focus: bool,
            ) {
                self.auction_id_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Auction ID ")
                        .title_alignment(Alignment::Left),
                );
                self.auction_id_textarea
                    .set_style(Style::default().fg(ratatui::style::Color::White));
                self.auction_id_textarea.set_style(Style::default());
                self.auction_id_textarea
                    .set_placeholder_style(Style::default().dark_gray());

                self.amount_textarea.set_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Amount ")
                        .title_alignment(Alignment::Left),
                );
                self.amount_textarea
                    .set_style(Style::default().fg(ratatui::style::Color::White));
                self.amount_textarea.set_style(Style::default());
                self.amount_textarea
                    .set_placeholder_style(Style::default().dark_gray());

                match self.field {
                    Field::AuctionId if focus && matches!(self.private_key_textarea, None) => {
                        self.auction_id_textarea
                            .set_placeholder_style(Style::default().white());
                        self.auction_id_textarea.set_style(Style::default().white());
                        self.auction_id_textarea.set_block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Auction ID ".bold())
                                .title_alignment(Alignment::Left)
                                .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                        );
                    }
                    Field::Amount if focus && matches!(self.private_key_textarea, None) => {
                        self.amount_textarea
                            .set_placeholder_style(Style::default().white());
                        self.amount_textarea.set_style(Style::default().white());
                        self.amount_textarea.set_block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_set(border::DOUBLE)
                                .title(" Amount ".bold())
                                .title_alignment(Alignment::Left)
                                .style(Style::default().fg(ratatui::style::Color::LightYellow)),
                        );
                    }
                    _ => {}
                };

                let [_, r, _] = Layout::horizontal([
                    Constraint::Fill(1),
                    Constraint::Percentage(70),
                    Constraint::Fill(1),
                ])
                .areas(*r);

                let [_, lsa, _, ld, _] = Layout::default()
                    .direction(ratatui::layout::Direction::Vertical)
                    .constraints([
                        Constraint::Min(3),
                        Constraint::Length(3),
                        Constraint::Min(2),
                        Constraint::Length(3),
                        Constraint::Min(3),
                    ])
                    .areas(r);

                f.render_widget(&self.auction_id_textarea, lsa);
                f.render_widget(&self.amount_textarea, ld);

                if let Some(p) = self.popup.clone() {
                    render_popup(f, p);
                }

                if let Some(p) = self.private_key_textarea.as_mut() {
                    if !focus {
                        p.set_block(private_key_block());
                    } else {
                        p.set_block(private_key_block_focus());
                    }
                    self.popup = None;
                    render_private_key_popup(f, &r, &p);
                }
            }
        }
    }

    #[derive(Clone)]
    pub enum Area {
        Menu,
        List,
        Body,
    }

    pub struct Dashboard {
        public_key: String,
        page: Page,
        area: Area,
        options_state: ListState,
        options: HashMap<(Page, usize), Box<dyn Section>>,
    }

    impl Dashboard {
        pub fn new(node: &str, public_key: &str) -> Self {
            let mut options_state = ListState::default();
            options_state.select(Some(1));

            let mut options: HashMap<(Page, usize), Box<dyn Section>> = HashMap::new();

            options.insert(
                (Page::Auctions, 1),
                Box::new(CreateAuction::new(node.to_string(), public_key.to_string())),
            );
            options.insert(
                (Page::Auctions, 2),
                Box::new(Bid::new(node.to_string(), public_key.to_string())),
            );

            Self {
                public_key: public_key.to_string(),
                page: Page::Auctions,
                area: Area::Menu,
                options_state,
                options,
            }
        }

        pub fn option(&mut self) -> &mut Box<dyn Section> {
            match self.options.get_mut(&(
                self.page.clone(),
                match self.options_state.selected() {
                    Some(s) => s,
                    _ => unreachable!(),
                },
            )) {
                Some(o) => o,
                _ => unreachable!(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Screen for Dashboard {
        async fn handle_io(&mut self, input: Input) -> Option<Box<dyn Screen + Send>> {
            match input {
                Input {
                    key: Key::Char('s'),
                    ctrl: true,
                    ..
                } => {
                    if !self.option().has_popup() {
                        match self.area {
                            Area::List => self.area = Area::Body,
                            Area::Body => self.area = Area::Menu,
                            Area::Menu => self.area = Area::List,
                        }
                    }
                }

                Input {
                    key: Key::Right, ..
                } => match self.area {
                    Area::Menu => self.page = self.page.next(),
                    Area::Body => {
                        if let Some(s) = self.option().handle_io(input).await {
                            *self.option() = s;
                        }
                    }
                    _ => {}
                },

                Input { key: Key::Left, .. } => match self.area {
                    Area::Menu => self.page = self.page.previous(),
                    Area::Body => {
                        if let Some(s) = self.option().handle_io(input).await {
                            *self.option() = s;
                        }
                    }
                    _ => {}
                },

                Input { key: Key::Down, .. } => match self.area {
                    Area::List => self.options_state.select_next(),
                    Area::Body => {
                        if let Some(s) = self.option().handle_io(input).await {
                            *self.option() = s;
                        }
                    }
                    _ => {}
                },

                Input { key: Key::Up, .. } => match self.area {
                    Area::List => self.options_state.select_previous(),
                    Area::Body => {
                        if let Some(s) = self.option().handle_io(input).await {
                            *self.option() = s;
                        }
                    }
                    _ => {}
                },
                _ => {
                    if let Area::Body = self.area {
                        if let Some(s) = self.option().handle_io(input).await {
                            *self.option() = s;
                        }
                    }
                }
            }
            None
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let size = f.area();

            let block = Block::default()
                .title_bottom(
                    "Use ↑/↓/←/→ to move, ^S to switch window, enter to continue, ^X to quit",
                )
                .title_alignment(Alignment::Center);
            f.render_widget(block, size);

            let [_, centered_menu, _, centered, _] = Layout::vertical([
                Constraint::Min(2),
                Constraint::Min(3),
                Constraint::Length(1),
                Constraint::Percentage(70),
                Constraint::Min(2),
            ])
            .areas(size);

            let menu = Tabs::new(
                Page::all()
                    .iter()
                    .map(|p| Line::from(Span::styled(p.clone(), Style::default())))
                    .collect::<Vec<Line>>(),
            )
            .divider("*")
            .block(match self.area {
                Area::Menu => Block::bordered()
                    .title(" Blocktion ".bold().light_yellow())
                    .border_style(Style::default().light_yellow()),
                _ => Block::bordered().title(" Blocktion "),
            })
            .highlight_style(Style::default().bold())
            .select(match self.page.clone().into() {
                Some(i) => i as usize,

                None => 0,
            });
            f.render_widget(menu, centered_menu);

            let [list_layout, _, body_layout] = Layout::horizontal([
                Constraint::Fill(10),
                Constraint::Min(1),
                Constraint::Percentage(80),
            ])
            .areas(centered);

            let list = List::new([" Available", " Create", " Bid"])
                .highlight_style(Style::default().bold())
                .highlight_symbol(" *")
                .scroll_padding(1)
                .block(match self.area {
                    Area::List => Block::bordered()
                        .title(" Options ".bold().light_yellow())
                        .border_style(Style::default().light_yellow()),
                    _ => Block::bordered().title(" Options "),
                });
            f.render_stateful_widget(list, list_layout, &mut self.options_state);

            let page = match self.area {
                Area::Body => Block::bordered()
                    .title(self.option().title().bold())
                    .border_style(Style::default().light_yellow()),
                _ => Block::bordered().title(self.option().title()),
            };
            f.render_widget(page, body_layout);

            let area = self.area.clone();

            self.option()
                .render(&body_layout, f, matches!(area, Area::Body));
        }
    }
}

mod bye {
    use crate::Screen;
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        widgets::Paragraph,
    };
    use ratatui_textarea::Input;
    use std::{process::exit, time::Duration};
    use tokio::time::sleep;

    pub const BYE_TIME: Duration = Duration::from_secs(1);

    pub struct Bye;

    #[async_trait::async_trait]
    impl Screen for Bye {
        async fn handle_io(&mut self, _input: Input) -> Option<Box<dyn Screen + Send>> {
            {
                tokio::spawn(async move {
                    sleep(BYE_TIME).await;
                    ratatui::restore();
                    exit(0);
                });
            }

            None
        }

        fn render(&mut self, f: &mut ratatui::prelude::Frame) {
            let [_, l, _] = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(1),
                Constraint::Fill(1),
            ])
            .areas(f.area());
            f.render_widget(
                Paragraph::new("See you space cowboy...")
                    .centered()
                    .alignment(Alignment::Center),
                l,
            );
        }
    }
}

struct App {
    current_screen: Box<dyn Screen>,
}

impl App {
    fn new(node: String) -> Self {
        Self {
            current_screen: Box::new(LogKeys::new(node)),
            //current_screen: Box::new(Dashboard::new(&node, "blabla")),
        }
    }

    async fn run(&mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| self.current_screen.render(frame))?;

            let input = event::read()?.into();

            if let Input {
                key: Key::Char('x'),
                ctrl: true,
                ..
            } = input
            {
                let mut bye = Bye;
                bye.handle_io(Input::default()).await;
                loop {
                    terminal.draw(|frame| bye.render(frame))?;
                }
            }

            if let Some(screen) = self.current_screen.handle_io(input).await {
                self.current_screen = screen;
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    node: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    color_eyre::install()?;
    let terminal = ratatui::init();
    let mut app = App::new(args.node);
    let result = app.run(terminal).await;
    result
}
