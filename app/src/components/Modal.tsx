// app/src/components/Modal.tsx
// Accessible modal dialog: role=dialog + aria-modal, labelled by its title,
// Escape and scrim click close it, focus moves in on open, Tab is trapped
// inside, and focus returns to whatever opened it on close

import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { X } from "lucide-react";
import IconButton from "@/components/IconButton";

type Props = {
  title: string;
  onClose: () => void;
  children: ReactNode;
  /** Extra class on the dialog box (width variants). */
  className?: string;
};

const kFocusable =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export default function Modal({ title, onClose, children, className }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    return () => {
      // Restore focus only if it is still inside the (now removed) dialog or
      // nowhere; never steal it from something the user moved to
      if (opener !== null && opener.isConnected) opener.focus();
    };
  }, []);

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      onCloseRef.current();
      return;
    }
    if (e.key !== "Tab") return;
    const root = dialogRef.current;
    if (root === null) return;
    const items = Array.from(root.querySelectorAll<HTMLElement>(kFocusable));
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="modal-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={dialogRef}
        className={className !== undefined ? `modal ${className}` : "modal"}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={onKeyDown}
      >
        <div className="panel-head">
          <span className="panel-title" id={titleId}>
            {title}
          </span>
          <div className="spacer" />
          <IconButton ref={closeRef} tip="Close" onClick={onClose}>
            <X size={14} />
          </IconButton>
        </div>
        {children}
      </div>
    </div>
  );
}
