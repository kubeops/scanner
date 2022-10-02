package v1alpha1

type Summary struct {
	SchemaVersion int             `json:"SchemaVersion"`
	ArtifactName  string          `json:"ArtifactName"`
	ArtifactType  string          `json:"ArtifactType"`
	Metadata      ImageMetadata   `json:"Metadata"`
	Results       []SummaryResult `json:"Results"`
}

type Report struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      ImageMetadata `json:"Metadata"`
	Results       []Result      `json:"Results"`
}

type ImageOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type ImageHistory struct {
	Created    MyTime `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
	Comment    string `json:"comment,omitempty"`
}

type ImageRootfs struct {
	Type    string   `json:"type"`
	DiffIds []string `json:"diff_ids"`
}

type ImageRuntimeConfig struct {
	Cmd         []string          `json:"Cmd"`
	Env         []string          `json:"Env,omitempty"`
	Image       string            `json:"Image,omitempty"`
	Entrypoint  []string          `json:"Entrypoint,omitempty"`
	Labels      map[string]string `json:"Labels,omitempty"`
	ArgsEscaped bool              `json:"ArgsEscaped,omitempty"`
	StopSignal  string            `json:"StopSignal,omitempty"`
}

type ImageConfig struct {
	Architecture  string             `json:"architecture"`
	Author        string             `json:"author,omitempty"`
	Container     string             `json:"container,omitempty"`
	Created       MyTime             `json:"created"`
	DockerVersion string             `json:"docker_version,omitempty"`
	History       []ImageHistory     `json:"history"`
	Os            string             `json:"os"`
	Rootfs        ImageRootfs        `json:"rootfs"`
	Config        ImageRuntimeConfig `json:"config"`
}

type ImageMetadata struct {
	Os          ImageOS     `json:"OS"`
	ImageID     string      `json:"ImageID"`
	DiffIDs     []string    `json:"DiffIDs"`
	RepoTags    []string    `json:"RepoTags"`
	RepoDigests []string    `json:"RepoDigests"`
	ImageConfig ImageConfig `json:"ImageConfig"`
}

type VulnerabilityLayer struct {
	Digest string `json:"Digest,omitempty"`
	DiffID string `json:"DiffID"`
}

type VulnerabilityDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type CVSSNvd struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

type CVSSRedhat struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

type CVSS struct {
	Nvd    *CVSSNvd    `json:"nvd,omitempty"`
	Redhat *CVSSRedhat `json:"redhat,omitempty"`
}

type Vulnerability struct {
	VulnerabilityID  string                  `json:"VulnerabilityID"`
	PkgName          string                  `json:"PkgName"`
	InstalledVersion string                  `json:"InstalledVersion"`
	Layer            VulnerabilityLayer      `json:"Layer"`
	SeveritySource   string                  `json:"SeveritySource"`
	PrimaryURL       string                  `json:"PrimaryURL"`
	DataSource       VulnerabilityDataSource `json:"DataSource"`
	Title            string                  `json:"Title,omitempty"`
	Description      string                  `json:"Description"`
	Severity         string                  `json:"Severity"`
	CweIDs           []string                `json:"CweIDs,omitempty"`
	Cvss             CVSS                    `json:"CVSS,omitempty"`
	References       []string                `json:"References"`
	PublishedDate    *MyTime                 `json:"PublishedDate,omitempty"`
	LastModifiedDate *MyTime                 `json:"LastModifiedDate,omitempty"`
	FixedVersion     string                  `json:"FixedVersion,omitempty"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
}

type SummaryResult struct {
	Target          string         `json:"Target"`
	Class           string         `json:"Class"`
	Type            string         `json:"Type"`
	Vulnerabilities map[string]int `json:"Vulnerabilities,omitempty"`
}
