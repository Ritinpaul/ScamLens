import React, { useState, useRef, useEffect } from 'react';
import ImageOutlined from '@mui/icons-material/ImageOutlined';
import DescriptionOutlined from '@mui/icons-material/DescriptionOutlined';
import CloudUploadOutlined from '@mui/icons-material/CloudUploadOutlined';
import SearchOutlined from '@mui/icons-material/SearchOutlined';

interface InputAreaProps {
  onAnalyzeText: (text: string) => void;
  onAnalyzeImage: (file: File) => void;
  isAnalyzing: boolean;
  disabled: boolean;
}

const PROGRESS_STAGES = [
  'Reading message and normalizing text...',
  'Extracting characters via local high-resolution OCR...',
  'Analyzing context and psychological pressure with local Llama 3...',
  'Verifying URLs, credential requests, and payment patterns...',
  'Synthesizing final safety verdict...',
];

export const InputArea: React.FC<InputAreaProps> = ({
  onAnalyzeText,
  onAnalyzeImage,
  isAnalyzing,
  disabled,
}) => {
  const [activeTab, setActiveTab] = useState<'screenshot' | 'text'>('screenshot');
  const [textInput, setTextInput] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [progressStageIdx, setProgressStageIdx] = useState(0);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Rotate progress stages during long local model inference
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isAnalyzing) {
      setProgressStageIdx(0);
      timer = setInterval(() => {
        setProgressStageIdx((prev) => (prev < PROGRESS_STAGES.length - 1 ? prev + 1 : prev));
      }, 11000);
    }
    return () => clearInterval(timer);
  }, [isAnalyzing]);

  // Clean up object URLs to avoid memory leaks
  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const handleFileChange = (file: File | null) => {
    if (!file) return;
    if (previewUrl) URL.revokeObjectURL(previewUrl);

    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleClearImage = () => {
    setSelectedFile(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleAnalyze = () => {
    if (activeTab === 'screenshot' && selectedFile) {
      onAnalyzeImage(selectedFile);
    } else if (activeTab === 'text' && textInput.trim()) {
      onAnalyzeText(textInput.trim());
    }
  };

  const isSubmitDisabled =
    disabled ||
    isAnalyzing ||
    (activeTab === 'screenshot' && !selectedFile) ||
    (activeTab === 'text' && !textInput.trim());

  return (
    <div className="panel input-panel">
      <div className="input-tabs" role="tablist" aria-label="Input Method">
        <button
          className={`tab-btn ${activeTab === 'screenshot' ? 'active' : ''}`}
          onClick={() => setActiveTab('screenshot')}
          role="tab"
          aria-selected={activeTab === 'screenshot'}
        >
          <ImageOutlined style={{ fontSize: '1rem', verticalAlign: 'middle', marginRight: '0.35rem' }} />
          Screenshot
        </button>
        <button
          className={`tab-btn ${activeTab === 'text' ? 'active' : ''}`}
          onClick={() => setActiveTab('text')}
          role="tab"
          aria-selected={activeTab === 'text'}
        >
          <DescriptionOutlined style={{ fontSize: '1rem', verticalAlign: 'middle', marginRight: '0.35rem' }} />
          Paste Text
        </button>
      </div>

      {activeTab === 'screenshot' ? (
        <div className="screenshot-tab-content">
          {previewUrl ? (
            <div className="image-preview-container">
              <img
                src={previewUrl}
                alt="Uploaded screenshot preview"
                className="image-preview"
              />
              <div className="image-preview-actions">
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isAnalyzing}
                >
                  Change Image
                </button>
                <button
                  type="button"
                  className="secondary-btn"
                  onClick={handleClearImage}
                  disabled={isAnalyzing}
                >
                  Remove
                </button>
              </div>
            </div>
          ) : (
            <div
              className={`dropzone ${isDragOver ? 'drag-active' : ''}`}
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
              }}
            >
              <div className="dropzone-icon">
                <CloudUploadOutlined style={{ fontSize: '2.5rem', color: 'var(--text-muted)' }} />
              </div>
              <div className="dropzone-label">Drop a suspicious message screenshot here, or click to browse</div>
              <div className="dropzone-hint">Supports PNG, JPEG, WebP up to 10MB • Processed locally via EasyOCR</div>
            </div>
          )}

          <input
            type="file"
            ref={fileInputRef}
            className="file-input-hidden"
            accept="image/png, image/jpeg, image/webp"
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) {
                handleFileChange(e.target.files[0]);
              }
            }}
          />
        </div>
      ) : (
        <div className="text-tab-content">
          <textarea
            className="text-input-area"
            placeholder="Paste a suspicious SMS, WhatsApp message, email, or notification here..."
            value={textInput}
            onChange={(e) => setTextInput(e.target.value)}
            disabled={isAnalyzing}
            aria-label="Suspicious message input"
          />
        </div>
      )}

      {isAnalyzing && (
        <div className="progress-card" role="status" aria-live="polite">
          <div className="progress-header">
            <div className="spinner"></div>
            <span>{PROGRESS_STAGES[progressStageIdx]}</span>
          </div>
          <p className="progress-note">
            Inference runs 100% locally on your machine via Ollama. Processing typically takes 40–55 seconds without sending your data anywhere.
          </p>
        </div>
      )}

      <div className="action-row">
        <button
          className="analyze-btn"
          onClick={handleAnalyze}
          disabled={isSubmitDisabled}
        >
          <SearchOutlined style={{ fontSize: '1.1rem', verticalAlign: 'middle', marginRight: '0.4rem' }} />
          {isAnalyzing ? 'Analyzing...' : 'Analyze Message'}
        </button>
      </div>
    </div>
  );
};
