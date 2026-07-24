package llm

import (
	"context"
	"fmt"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/rs/zerolog/log"
	"os"
)

type ClaudeClient struct {
	Client              *anthropic.Client
	MessageHistory      []anthropic.BetaTextBlockParam
	MessageHistoryLimit int
	SystemPrompt        string
	Model               string
}

func NewClaudeClient(model string, systemPrompt string) (*ClaudeClient, error) {
	apikey := os.Getenv("ANTHROPIC_API_KEY")
	if apikey == "" {
		log.Error().Msg("claude: API key is missing")
		return nil, fmt.Errorf("audit: API key is missing")
	}

	baseURL := os.Getenv("OPENROUTER_BASE_URL")
	if baseURL == "" {
		return nil, fmt.Errorf("audit: OpenRouter base URL is missing")
	}

	cc := &ClaudeClient{
		Client:         anthropic.NewClient(option.WithAuthToken(apikey), option.WithBaseURL(baseURL)),
		MessageHistory: []anthropic.BetaTextBlockParam{},
		SystemPrompt:   systemPrompt,
		Model:          model,
	}
	return cc, nil
}

func (cc *ClaudeClient) SendTextMessage(ctx context.Context, text string, historyMessageKeepNum int) (string, error) {
	//if historyMessageKeepNum > len(cc.MessageHistory) {
	//	historyMessageKeepNum = len(cc.MessageHistory)
	//}
	//
	//messages := cc.MessageHistory[len(cc.MessageHistory)-historyMessageKeepNum:]

	log.Debug().Msgf("claude_send: %s", text)

	_ = historyMessageKeepNum

	messages := []anthropic.BetaMessageParam{
		NewBetaUserMessage(
			anthropic.BetaTextBlockParam{
				Text: anthropic.F(text),
				Type: anthropic.F(anthropic.BetaTextBlockParamTypeText),
				// CacheControl:
			},
		),
	}

	response, err := cc.Client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model: anthropic.F(cc.Model),
		// TODO: need count the number of token
		MaxTokens: anthropic.F(int64(4096)),
		System: anthropic.F([]anthropic.BetaTextBlockParam{
			{
				Text:         anthropic.F(cc.SystemPrompt),
				Type:         anthropic.F(anthropic.BetaTextBlockParamTypeText),
				CacheControl: anthropic.F(anthropic.BetaCacheControlEphemeralParam{Type: anthropic.F(anthropic.BetaCacheControlEphemeralTypeEphemeral)}),
			},
		}),
		Messages: anthropic.F(messages),
		Betas:    anthropic.F([]anthropic.AnthropicBeta{anthropic.AnthropicBetaPromptCaching2024_07_31}),
	})

	if err != nil {
		log.Error().Err(err).Msg("audit: send message failed")
		return "", err
	}

	answer := ""
	// extract message from response
	for _, block := range response.Content {
		if block.Type == anthropic.BetaContentBlockTypeText {
			// FIXME: may multiple blocks?
			answer = block.Text
			break
		}
	}

	log.Debug().Msgf("claude_accept: %s", answer)

	return answer, nil
}

func NewBetaUserMessage(blocks ...anthropic.BetaContentBlockParamUnion) anthropic.BetaMessageParam {
	return anthropic.BetaMessageParam{
		Role:    anthropic.F(anthropic.BetaMessageParamRoleUser),
		Content: anthropic.F(blocks),
	}
}

func (cc *ClaudeClient) tokenCount() {
	// TODO
}

func responseToParam() {

}
